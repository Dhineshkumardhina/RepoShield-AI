"""Pydantic schemas for authentication and user accounts."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"


class UserRegister(BaseModel):
    email: str = Field(..., pattern=EMAIL_REGEX, description="Valid email address", examples=["practitioner@xerova.com"])
    password: str = Field(..., min_length=8, max_length=128, description="Minimum 8 characters")


class UserLogin(BaseModel):
    email: str = Field(..., pattern=EMAIL_REGEX, description="Valid email address", examples=["practitioner@xerova.com"])
    password: str = Field(..., min_length=1, description="Account password")


class UserRead(BaseModel):
    id: str
    email: str
    account_status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserRead


class LogoutResponse(BaseModel):
    success: bool = True
    message: str = "Successfully logged out."
