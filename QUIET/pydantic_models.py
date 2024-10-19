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


# FLUTTERWAVE PAYMENT
class flutterwave_payment_pydantic_model(BaseModel):
    amount: str = Field(examples=["3000"])
    days_paid: int = Field(examples=[3])
    server_ip: str = Field(examples=["127.0.0.1"])
    server_location: str = Field(examples=["San Francisco, USA"])
    redirect_url: str = Field(examples=["https://google.com/"])

class verify_flutterwave_payment_pydantic_model(BaseModel):
    transaction_id: str = Field(examples=["7712579"])
    days_paid: int = Field(examples=[3])
    server_ip: str = Field(examples=["127.0.0.1"])
    server_location: str = Field(examples=["San Francisco, USA"])
