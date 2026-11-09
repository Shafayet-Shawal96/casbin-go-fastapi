from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

Name = Annotated[str, Field(min_length=1, max_length=255)]
OptionalText = Annotated[str | None, Field(default=None, max_length=255)]
Phone = Annotated[str | None, Field(default=None, max_length=32)]
RoleName = Annotated[str, Field(min_length=1, max_length=64)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NonEmptyPatch(StrictModel):
    @model_validator(mode="after")
    def require_a_field(self):
        if not self.model_fields_set:
            raise ValueError("at least one field is required")
        return self


class UserInfoUpdate(NonEmptyPatch):
    name: Name | None = None
    phone: Phone = None

    @model_validator(mode="after")
    def name_is_not_null(self):
        if "name" in self.model_fields_set and self.name is None:
            raise ValueError("name cannot be null")
        return self


class CompanyInfoUpdate(NonEmptyPatch):
    company_name: OptionalText = None
    department: OptionalText = None
    designation: OptionalText = None


class UserCreate(StrictModel):
    email: EmailStr
    password: str = Field(min_length=8)
    name: Name
    role: RoleName

    @model_validator(mode="after")
    def password_fits_bcrypt(self):
        # bcrypt only uses the first 72 bytes, so longer passwords are refused.
        if len(self.password.encode()) > 72:
            raise ValueError("password must be at most 72 bytes")
        return self


class RoleAssign(StrictModel):
    role: RoleName


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    name: str
    phone: str | None
    role: str
    is_active: bool
    company_name: str | None
    department: str | None
    designation: str | None
    created_at: datetime
    updated_at: datetime


class UserList(BaseModel):
    items: list[UserOut]
    total: int
    limit: int
    offset: int
