import os

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["INTERNAL_TOKEN"] = "test-token"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.models import Role, User

HEADERS = {"X-Internal-Token": "test-token", "X-User-Id": "1"}


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with Session() as db:
        for name in ("system-admin", "super-admin", "admin", "user"):
            db.add(Role(name=name, is_builtin=True))
        db.add(User(id=1, email="root@x.io", password_hash="HASH", name="Root", role="system-admin"))
        db.add(User(id=2, email="sup@x.io", password_hash="HASH", name="Sup", role="super-admin"))
        db.add(User(id=3, email="u@x.io", password_hash="HASH", name="U", role="user"))
        db.commit()

    def override():
        with Session() as db:
            yield db

    app.dependency_overrides[get_db] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def new_user(**overrides):
    return {"email": "n@x.io", "password": "password123", "name": "N", "role": "user", **overrides}


@pytest.mark.parametrize("headers", [{}, {"X-Internal-Token": "wrong"}])
def test_rejects_missing_or_wrong_internal_token(client, headers):
    assert client.get("/users", headers=headers).status_code == 401


def test_responses_never_include_password_hash(client):
    body = client.get("/users", headers=HEADERS).text
    assert "password_hash" not in body and "HASH" not in body
    assert "password" not in client.post("/users", json=new_user(), headers=HEADERS).text


@pytest.mark.parametrize(
    "path,payload",
    [
        ("/users/3/info", {"role": "admin"}),
        ("/users/3/info", {"name": "X", "is_active": False}),
        ("/users/3/info", {"company_name": "X"}),
        ("/users/3/company", {"name": "X"}),
        ("/users/3/info", {}),
        ("/users/3/info", {"name": None}),
    ],
)
def test_patch_rejects_fields_outside_allowlist(client, path, payload):
    assert client.patch(path, json=payload, headers=HEADERS).status_code == 422


def test_patch_updates_only_sent_fields(client):
    res = client.patch("/users/3/info", json={"phone": "123"}, headers=HEADERS)
    assert res.status_code == 200
    assert res.json()["phone"] == "123" and res.json()["name"] == "U"


def test_create_user_rejects_extra_fields(client):
    res = client.post("/users", json=new_user(is_active=False), headers=HEADERS)
    assert res.status_code == 422


def test_create_user_rejects_system_admin(client):
    res = client.post("/users", json=new_user(role="system-admin"), headers=HEADERS)
    assert res.status_code == 403


def test_create_user_rejects_unknown_role(client):
    assert client.post("/users", json=new_user(role="nope"), headers=HEADERS).status_code == 422


def test_create_user_rejects_duplicate_email(client):
    assert client.post("/users", json=new_user(email="u@x.io"), headers=HEADERS).status_code == 409


def test_create_user_rejects_password_over_72_bytes(client):
    assert client.post("/users", json=new_user(password="x" * 73), headers=HEADERS).status_code == 422


def test_assign_role_success(client):
    res = client.put("/users/3/role", json={"role": "admin"}, headers=HEADERS)
    assert res.status_code == 200 and res.json()["role"] == "admin"


def test_assign_role_rejects_system_admin_value(client):
    res = client.put("/users/3/role", json={"role": "system-admin"}, headers=HEADERS)
    assert res.status_code == 403


def test_assign_role_rejects_changing_a_system_admin(client):
    headers = {**HEADERS, "X-User-Id": "2"}
    res = client.put("/users/1/role", json={"role": "user"}, headers=headers)
    assert res.status_code == 403


def test_assign_role_rejects_self(client):
    headers = {**HEADERS, "X-User-Id": "2"}
    res = client.put("/users/2/role", json={"role": "admin"}, headers=headers)
    assert res.status_code == 403


def test_assign_role_missing_target(client):
    assert client.put("/users/99/role", json={"role": "user"}, headers=HEADERS).status_code == 404


def test_me_uses_actor_header(client):
    res = client.get("/me", headers={**HEADERS, "X-User-Id": "3"})
    assert res.json()["id"] == 3


def test_deactivate_is_idempotent(client):
    for _ in range(2):
        res = client.post("/users/3/deactivate", headers=HEADERS)
        assert res.status_code == 200 and res.json()["is_active"] is False
