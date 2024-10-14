from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class signup_User(BaseModel):
    # id: int
    email: EmailStr = Field(examples=["test@example.com"])
    username: str = Field(examples=["test_username"])
    password: str = Field(examples=["testpassword"])


class signin_User(BaseModel):
    # use either username/email
    email: str = Field(examples=["test@example.com"])
    password: str = Field(examples=["testpassword"])


class get_User(BaseModel):
    # use either username/email
    email: str = Field(examples=["test@example.com"])


class update_user_model(BaseModel):
    # can only update username
    username: Optional[str] = Field(examples=["username-updated"])

class send_otp_model(BaseModel):
    email: EmailStr = Field(examples=["test@example.com"])

class verify_otp_model(BaseModel):
    user_id: str = Field(examples=["usr181396658"])
    otp: int = Field(examples=["176713"])

class change_password_model(BaseModel):
    password: str = Field(examples=["changedtestpassword"])
