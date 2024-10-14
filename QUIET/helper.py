from email_validator import validate_email, EmailNotValidError
import jwt
import os
import time
import json
import re
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends


def email_validator(usr_email):
    try:
        emailinfo = validate_email(usr_email, check_deliverability=False)
        return (emailinfo.normalized).lower()
    except EmailNotValidError as e:
        return {
            "statusCode": 400,
            "error": str(e)
        }
    except exception as e:
        raise


def decode_jwt(token: str):
    #  [ TOKENIZATION ]
    JWT_SECRET = os.getenv("SECRET")
    JWT_ALGORITHM = os.getenv("ALGORITHM")

    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded_token  # if decoded_token["expires"] >= time.time() else None
    except Exception as e:
        return {
            "statusCode": 400,
            "err": str(e)
        }


def generate_token(data):
    payload_list = ["email", "username"]
    payload = {}
    for i in payload_list:
        payload[i] = data[i]
    payload["expires"] = time.time() + 86400  # expiry time of 24 hrs

    #  [ TOKENIZATION ]
    JWT_SECRET = os.getenv("SECRET")
    JWT_ALGORITHM = os.getenv("ALGORITHM")
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return {
        "statusCode": 200,
        "message": "success",
        "token": token
    }


#  [ GET BEARER TOKEN FROM 'AUTHORIZATION' HEADER ]
security = HTTPBearer()
def get_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Token",
        )
    return credentials.credentials
