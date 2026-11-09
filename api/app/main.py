import os
import secrets
from typing import Annotated

import bcrypt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .db import get_db
from .models import SYSTEM_ADMIN_ROLE, Role, User
from .schemas import (
    CompanyInfoUpdate,
    RoleAssign,
    UserCreate,
    UserInfoUpdate,
    UserList,
    UserOut,
)

INTERNAL_TOKEN = os.environ["INTERNAL_TOKEN"]


def require_internal_token(
    x_internal_token: Annotated[str | None, Header()] = None,
) -> None:
    if x_internal_token is None or not secrets.compare_digest(
        x_internal_token.encode(), INTERNAL_TOKEN.encode()
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid internal token")


def actor_id(x_user_id: Annotated[int, Header()]) -> int:
    return x_user_id


app = FastAPI(title="User service", dependencies=[Depends(require_internal_token)])

Db = Annotated[Session, Depends(get_db)]
ActorId = Annotated[int, Depends(actor_id)]


def get_user_or_404(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return user


def validate_assignable_role(db: Session, role: str) -> None:
    if role == SYSTEM_ADMIN_ROLE:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "system-admin cannot be assigned")
    if db.get(Role, role) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "role does not exist")


def apply_patch(db: Session, user: User, patch: UserInfoUpdate | CompanyInfoUpdate) -> User:
    for field, value in patch.model_dump(exclude_unset=True).items():
        setattr(user, field, value)
    db.commit()
    db.refresh(user)
    return user


@app.get("/users", response_model=UserList)
def get_all_users(
    db: Db,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    items = db.scalars(select(User).order_by(User.id).limit(limit).offset(offset)).all()
    total = db.scalar(select(func.count()).select_from(User))
    return UserList(
        items=[UserOut.model_validate(u) for u in items],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@app.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, db: Db):
    validate_assignable_role(db, body.role)
    user = User(
        email=body.email.lower(),
        password_hash=bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode(),
        name=body.name,
        role=body.role,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "email already exists") from None
    db.refresh(user)
    return user


@app.get("/me", response_model=UserOut)
def me(db: Db, actor: ActorId):
    return get_user_or_404(db, actor)


@app.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int, db: Db):
    return get_user_or_404(db, user_id)


@app.patch("/users/{user_id}/info", response_model=UserOut)
def update_user_info(user_id: int, body: UserInfoUpdate, db: Db):
    return apply_patch(db, get_user_or_404(db, user_id), body)


@app.patch("/users/{user_id}/company", response_model=UserOut)
def update_company_info(user_id: int, body: CompanyInfoUpdate, db: Db):
    return apply_patch(db, get_user_or_404(db, user_id), body)


@app.post("/users/{user_id}/deactivate", response_model=UserOut)
def deactivate_user(user_id: int, db: Db):
    user = get_user_or_404(db, user_id)
    user.is_active = False
    db.commit()
    db.refresh(user)
    return user


@app.put("/users/{user_id}/role", response_model=UserOut)
def assign_role(user_id: int, body: RoleAssign, db: Db, actor: ActorId):
    user = get_user_or_404(db, user_id)
    if user_id == actor:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cannot change your own role")
    if user.role == SYSTEM_ADMIN_ROLE:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cannot change a system-admin's role")
    validate_assignable_role(db, body.role)
    user.role = body.role
    db.commit()
    db.refresh(user)
    return user
