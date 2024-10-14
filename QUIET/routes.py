from QUIET import app
from fastapi import status, Depends, HTTPException, File, UploadFile, Form, Depends

from QUIET.models import (
    User, user_otp
)
from QUIET.helper import (
    email_validator, generate_token,
    decode_jwt, get_token
)
from QUIET.pydantic_models import (
    signup_User, signin_User,
    get_User, update_user_model,
    send_otp_model, verify_otp_model,
    change_password_model
)

from typing import Annotated
from sqlalchemy.orm import Session
from database import SessionLocal
from random import randint

# for mail service
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# import jwt
import time
import os
import re
import httpx
from httpx import Timeout
from passlib.hash import bcrypt_sha256


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
db_dependency = Annotated[Session, Depends(get_db)]


#  [ INDEX/MISC ]
@app.get("/", status_code=status.HTTP_200_OK)
def index():
    return {
        "statusCode": 200,
        "message": "nothing to see here!"
    }


#--------------------------------
#  [ AUTH :-: SIGN-UP & LOGIN]

@app.post("/account/signup", tags=["AUTH"])
@app.post("/account/signup/", tags=["AUTH"])
def sign_up(data: signup_User, db: db_dependency):
    """
    Endpoint to sign-up users
    """
    #  [ VALIDATE AND NORMALIZE EMAIL ]
    data.email = email_validator(data.email)


    #  check if user email and/or username already exists
    check_user = db.query(User).filter(User.email == data.email).first()
    if check_user is not None:
        raise HTTPXException(status_code=400, detail="User already exists")

    check_user = db.query(User).filter(user.username == data.username).first()
    if check_user is not None:
        raise HTTPException(status_code=400, detail="User already exists")



    #  [ hash user's password before saving to db ]
    hash_bcrypt = bcrypt_sha256.hash(data.password)
    #  [ reversed user password ]
    slug_ = (data.password)[::-1]


    # store to db
    data = data.dict()
    new_user = User(
        email=data["email"],
        username = data["username"],
        password=hash_bcrypt,
        slug=slug_,
        is_activated=False,
        days_paid=0, # users will get free config for 2 days only after successful activation
        server_ip="127.0.0.1",  # a placeholder
        server_location="local",  # a placeholder
        config_file="config_name"  # a placeholder
    )
    db.add(new_user)
    db.commit()


    token = generate_token(data)
    token = token["token"]

    #  [ SEND-WELCOME-MAIL-TO-USERS - smtp,etc]

    return {
        "statusCode": 201,
        "message": "Account created successfully! Activate your account!",
        "token": token,
        "email": (data["email"]).lower()
    }, 201



@app.post("/account/login", status_code=status.HTTP_200_OK, tags=["AUTH"])
@app.post("/account/login/", status_code=status.HTTP_200_OK, tags=["AUTH"])
def sign_in(data: signin_User, db: db_dependency):
    """
    Endpoint to sign-in users
    """
    #  [ VALIDATE AND NORMALIZE EMAIL ]
    data.email = email_validator(data.email)
    data = data.dict()

    check_user = db.query(User).filter((User.email == data["email"]) | (User.username == data["email"])).first()

    if check_user is None:
        raise HTTPException(status_code=400, detail="invalid email or password!")

    data["username"] = check_user.username
    data["email"] = check_user.email

    #  [ GATHER [PASSWORD]-/-[HASHES] AND VERIFY ]
    user_input_password = data["password"]
    user_password_hash = check_user.password

    if bcrypt_sha256.verify(user_input_password, user_password_hash) is False:
        raise HTTPException(status_code=400, detail="invalid email or password!")


    #  [ GENERATE TOKEN ON SUCCESS ]
    token = generate_token(data)
    token = token["token"]

    if check_user.is_activated is False:
        return {
            "statusCode": 200,
            "message": "login successful!",
            "err": "Activate your account!",
            "token": token
        }
    return {
        "statusCode": 200,
        "message": "login successful!",
        "token": token
    }

