from QUIET import app
from fastapi import status, Depends, HTTPException, File, UploadFile, Form, Depends

from QUIET.models import (
    User, user_otp, servers,
    user_config
)
from QUIET.helper import (
    email_validator, generate_token,
    decode_jwt, get_token
)
from QUIET.pydantic_models import (
    signup_User, signin_User, update_user_model,
    flutterwave_payment_pydantic_model,
    verify_flutterwave_payment_pydantic_model,
    paystack_payment_pydantic_model,
    verify_paystack_payment_pydantic_model,
    send_otp_model, verify_otp_model,
    change_password_model, get_config_pydantic_model
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
        raise HTTPException(status_code=400, detail="User already exists")

    check_user = db.query(User).filter(User.username == data.username).first()
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

    check_user = db.query(User).filter(User.email == data["email"]).first()
    if check_user is None:
        check_user = db.query(User).filter(User.username == data["email"]).first()
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


# ------------------------------
#  [ USER ACCOUNT AND PROFILE ]

@app.get("/account/user_profile", status_code=status.HTTP_200_OK, tags=["USER"])
@app.get("/account/user_profile/", status_code=status.HTTP_200_OK, tags=["USER"])
def get_user_profile(db: db_dependency, token: str = Depends(get_token)):
    # To get logged in user
    try:
        payload = decode_jwt(token)
        token_expiry = payload.pop("expires")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Token!")


    #  [ CHECK TOKEN EXPIRY ]
    if token_expiry <= time.time():
        raise HTTPException(status_code=400, detail={"message": "Token Expired! Kindly login again!"})

    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.email == payload["email"]).first()
    if check_user is None:
        raise HTTPException(status_code=400, detail={"message": "Invalid Token! Kindly login again!"})


    data = {}
    data["email"] = check_user.email
    data["username"] = check_user.username

    return {
        "statusCode": 200,
        "data": data
    }


#  [ !use DELETE request to delete logged-in user profile! ]
@app.delete("/account/user_profile", status_code=status.HTTP_200_OK, tags=["USER"])
@app.delete("/account/user_profile/", status_code=status.HTTP_200_OK, tags=["USER"])
def delete_user_profile(db: db_dependency, token: str = Depends(get_token)):
    try:
        payload = decode_jwt(token)
        token_expiry = payload.pop("expires")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Token!")


    if token_expiry <= time.time():
        raise HTTPException(status_code=400, detail={"message": "Token Expired! Kindly login again!"})

    check_user = db.query(User).filter(User.email == payload["email"]).first()
    if check_user is None:
        raise HTTPException(status_code=400, detail={"message": "Invalid Token! Kindly login again!"})

    db.delete(check_user)
    db.commit()

    return {
        "statusCode": 200,
        "message": "{} deleted successfully!".format(check_user.username)
    }


#  [ !use POST request to update logged-in user profile! ]
@app.post("/account/user_profile", status_code=status.HTTP_200_OK, tags=["USER"])
@app.post("/account/user_profile/", status_code=status.HTTP_200_OK, tags=["USER"])
def update_user_profile(
    data: update_user_model,
    db: db_dependency,
    token: str = Depends(get_token)):
    """
    Update user profile
    """
    try:
        payload = decode_jwt(token)
        token_expiry = payload.pop("expires")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Token!")


    #  [ CHECK TOKEN EXPIRY ]
    if token_expiry <= time.time():
        raise HTTPException(status_code=400, detail={"message": "Token Expired! Kindly login again!"})

    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.email == payload["email"]).first()
    if check_user is None:
        raise HTTPException(status_code=400, detail={"message": "Invalid Token! Kindly login again!"})
    else:
        # explicitly validate each data
        if data.username is not None:
            check_user.username = data.username

    # commit changes if any
    db.commit()

    return {
        "statusCode": 200,
        "message": "successful! - user profile updated!"
    }


@app.post("/account/change_password", status_code=status.HTTP_200_OK, tags=["USER"])
@app.post("/account/change_password/", status_code=status.HTTP_200_OK, tags=["USER"])
def change_password(
    data: change_password_model,
    db: db_dependency,
    token: str = Depends(get_token)):
    #  [ DECODE JWT ]
    try:
        payload = decode_jwt(token)
        token_expiry = payload.pop("expires")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Token!")


    #  [ CHECK TOKEN EXPIRY ]
    if token_expiry <= time.time():
        raise HTTPException(status_code=400,
                detail={"message": "An Error Occurred! Kindly request new OTP!"})

    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.email == payload["email"]).first()
    if check_user is None:
        raise HTTPException(status_code=404, detail={"message": "Account not found!"})

    check_user.password = bcrypt_sha256.hash(data.password)
    check_user.slug_ = (data.password)[::-1]
    db.commit()

    return {
        "statusCode": 200,
        "message": "password changed successfully!"
    }


# [ FLUTTERWAVE PAYMENT ]
FLW_SECRET_KEY = os.getenv('FLW_SECRET_KEY')
FLW_BASE_URL = 'https://api.flutterwave.com/v3'

@app.post("/payment/flutterwave", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
@app.post("/payment/flutterwave/", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
def create_payment_flutterwave(data: flutterwave_payment_pydantic_model, db: db_dependency, token: str = Depends(get_token)):
    # [ DECODE JWT ]
    try:
        payload = decode_jwt(token)
        token_expiry = payload.pop("expires")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Token!")

    # [ CHECK TOKEN EXPIRY ]
    if token_expiry <= time.time():
        raise HTTPException(status_code=400, detail={"err": "Token Expired! Kindly login again!"})

    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.email == payload["email"]).first()
    if check_user is None:
        raise HTTPException(status_code=404, detail={"err": "Account not found!"})

    """
    if check_user.is_activated is False:
        raise HTTPException(status_code=400, detail={"err": "Kindly activate your account!"})
    """

    headers = {
        "Authorization": f"Bearer {FLW_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    data = data.dict()
    data["tx_ref"] = "REF-{}".format(randint(100000000, 999999999))
    data["currency"] = "NGN"
    data["payment_options"] = "card, account, googlepay, applepay"

    # depending on ip, query db to get price per day
    get_server = db.query(servers).filter(servers.server_ip == data["server_ip"]).first()

    if get_server is None:
        raise HTTPException(status_code=500, detail="server not found!")

    # if price exists for the server
    data["amount"] = str(get_server.price)

    amount_format = ""

    if "," in data["amount"]:
        amount_format = (data["amount"]).replace(",","")
    elif (data["amount"]).endswith(".00"):
        amount_format = data["amount"][:-3]

    if amount_format.endswith(".00"):
        amount_format = amount_format[:-3]
    elif "," in amount_format:
        amount_format = (amount_format).replace(",","")

    if len(amount_format) <= 0:
        amount_format = data["amount"]

    # flutterwave payment payload
    payload = {
        "tx_ref": data["tx_ref"],
        # "amount": int(amount_format) * per_dollar,
        "amount": int(amount_format) * int(data["days_paid"]),
        "currency": data["currency"],
        "redirect_url": data["redirect_url"],
        "payment_options": data["payment_options"],
        "customer": {
            "email": check_user.email,
            "name": "{}".format(check_user.username)
        },
        "customizations": {
            "title": "QUIET VPN Inc.",
            "logo": "https://luravpn.nyc3.digitaloceanspaces.com/country_icon/.misc/security.png"
        }
    }


    try:
        with httpx.Client(timeout=Timeout(60.0)) as client:
            # set timeout to 60 seconds
            response = client.post(f"{FLW_BASE_URL}/payments", json=payload, headers=headers)
    except httpx.TimeoutException as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    # return PaymentResponse(status="success", message="Payment created successfully", data=response.json())
    return {
        "statusCode": 200,
        "message": "Payment created successfully",
        "user": check_user.username,
        "days_paid": data["days_paid"],
        "server_ip": data["server_ip"],
        "server_location": get_server.location,
        "data": (response.json())["data"]
    }

@app.post("/payment/verify_flutterwave", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
@app.post("/payment/verify_flutterwave/", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
def verify_payment_flutterwave(data: verify_flutterwave_payment_pydantic_model, db: db_dependency):
    username = data.username

    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.username == username).first()
    if check_user is None:
        raise HTTPException(status_code=404, detail={"err": "Account not found!"})

    token = None
    token_obj = {
        "email": check_user.email,
        "username": check_user.username
    }

    """
    if check_user.is_activated is False:
        raise HTTPException(status_code=400, detail={"err": "Kindly activate your account!"})
    """

    headers = {
        "Authorization": f"Bearer {FLW_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    try:
        # for flutterwave
        with httpx.Client(timeout=Timeout(60.0)) as client:
            # set timeout to 60 seconds
            response = client.get("{FLW_BASE_URL}/transactions/{transaction_id}/verify".format(
                FLW_BASE_URL=FLW_BASE_URL, transaction_id=data.transaction_id
            ), headers=headers)
    except httpx.TimeoutException as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    data_ = {}
    output_ = (response.json())["data"]
    output_customer = (response.json())["data"]["customer"]
    
    data_["id"] = output_["id"] or None
    data_["status"] = output_["status"] or None
    data_["tx_ref"] = output_["tx_ref"] or None
    data_["flw_ref"] = output_["flw_ref"] or None
    data_["amount"] = output_["amount"] or None
    data_["currency"] = output_["currency"] or None
    data_["payment_type"] = output_["payment_type"] or None
    data_["username"] = output_customer["name"] or None
    data_["email"] = output_customer["email"] or None

    if data_["status"] == "successful":
        try:
            with httpx.Client(timeout=Timeout(60.0)) as client:
                # set timeout to 50 seconds
                response_2 = client.get("http://{server_ip}/create_peer/".format(
                    server_ip=data.server_ip
                ), headers={"Content-Type": "application/json"})

                bin_val = response_2.json()  # to confirm if request was sent to a valid ip_address
        except httpx.TimeoutException as e:
            # raise
            raise HTTPException(status_code=500, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail="invalid request! check server: {}".format(data.server_ip))
    else:
        return {
            "statusCode": 400,
            "err": "Payment Not Successful!",
            "message": "Payment Not Successful!"
        }

    try:
        # Save the config, server_ip, and days_paid to user_config table
        user_config_obj = db.query(user_config).filter(
            user_config.email == check_user.email,
            user_config.server_ip == data.server_ip  # Match the server_ip as well
        ).first()

        if not user_config_obj:
            # If no record exists, create a new one
            user_config_obj = user_config(
                email=check_user.email,
                server_ip=data.server_ip,
                config=response_2.json()["data"]["client_id"],  # Assuming the config name is in the response
                days_paid=int(data.days_paid) + 1
            )
            db.add(user_config_obj)
        else:
            # If a record exists, replace the existing one
            # Delete from vpn server
            try:
                with httpx.Client(timeout=Timeout(60.0)) as client:
                    response_3 = client.get("http://{server_ip}/revoke_peer/{config_file}/".format(server_ip=data.server_ip,
                                             config_file=user_config_obj.config),
                                             headers={"Content-Type": "application/json"}
                                         )
            except httpx.TimeoutException as e:
                pass
                # raise HTTPException(status_code=500, detail=str(e))

            # Replace in DB
            user_config_obj.server_ip = data.server_ip
            user_config_obj.config = response_2.json()["data"]["client_id"]  # Assuming the config name is in the response
            user_config_obj.days_paid += int(data.days_paid) + 1  # add up the remaining days with the new one
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Commit the changes
    db.commit()
    token = generate_token(token_obj)  # generate user token

    return {
        "statusCode": 200,
        "token": token,
        "days_paid": data.days_paid,
        "server_ip": data.server_ip,
        "server_location": data.server_location,
        "data": data_,
        "config_data": response_2.json()["data"]
    }



# [ PAYSTACK PAYMENT ]
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")
PAYSTACK_BASE_URL = "https://api.paystack.co/transaction"

@app.post("/payment/paystack", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
@app.post("/payment/paystack/", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
def create_payment_paystack(data: paystack_payment_pydantic_model, db: db_dependency, token: str = Depends(get_token)):
    # [ DECODE JWT ]
    try:
        payload = decode_jwt(token)
        token_expiry = payload.pop("expires")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Token!")

    # [ CHECK TOKEN EXPIRY ]
    if token_expiry <= time.time():
        raise HTTPException(status_code=400, detail={"err": "Token Expired! Kindly login again!"})

    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.email == payload["email"]).first()
    if check_user is None:
        raise HTTPException(status_code=404, detail={"err": "Account not found!"})

    """
    if check_user.is_activated is False:
        raise HTTPException(status_code=400, detail={"err": "Kindly activate your account!"})
    """

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    data = data.dict()

    # depending on ip, query db to get price per day
    get_server = db.query(servers).filter(servers.server_ip == data["server_ip"]).first()
    if get_server is None:
        raise HTTPException(status_code=500, detail="server not found!")

    # if price exists for the server
    data["amount"] = str(get_server.price)
    amount_format = ""

    if "," in data["amount"]:
        amount_format = (data["amount"]).replace(",","")
    elif (data["amount"]).endswith(".00"):
        amount_format = data["amount"][:-3]
    if amount_format.endswith(".00"):
        amount_format = amount_format[:-3]
    elif "," in amount_format:
        amount_format = (amount_format).replace(",","")
    if len(amount_format) <= 0:
        amount_format = data["amount"]

    # paystack payment payload
    payload = {
        "amount": str(int(amount_format) * 100 * int(data["days_paid"])),
        "email": check_user.email,
        "currency": "NGN",
        "callback_url": data["redirect_url"]
    }

    try:
        with httpx.Client(timeout=Timeout(60.0)) as client:
            # set timeout to 60 seconds
            response = client.post(f"{PAYSTACK_BASE_URL}/initialize", json=payload, headers=headers)
            response = (response.json())["data"]
    except httpx.TimeoutException as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
        
    # return PaymentResponse(status="success", message="Payment created successfully", data=response.json())
    return {
        "statusCode": 200,
        "message": "Payment created successfully",
        "user": check_user.username,
        "days_paid": data["days_paid"],
        "server_ip": data["server_ip"],
        "server_location": get_server.location,
        "response": response
    }

# [ VERIFY PAYSTACK PAYMENT ]
@app.post("/payment/paystack/verify", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
@app.post("/payment/paystack/verify/", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
def verify_paystack_payment(data: verify_paystack_payment_pydantic_model, db: db_dependency):
    username = data.username

    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.username == username).first()
    if check_user is None:
        raise HTTPException(status_code=404, detail={"err": "Account not found!"})

    token = None
    token_obj = {
        "email": check_user.email,
        "username": check_user.username
    }

    """
    if check_user.is_activated is False:
        raise HTTPException(status_code=400, detail={"err": "Kindly activate your account!"})
    """

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"
    }

    # data = data.dict()
    try:
        with httpx.Client(timeout=Timeout(60.0)) as client:
            # set timeout to 60 seconds
            response = client.get("{x}/verify/{y}".format(x=os.getenv("PAYSTACK_BASE_URL"), y=data.transaction_id), headers=headers)
            response = response.json()
    except httpx.TimeoutException as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
        
    # return PaymentResponse(status="success", message="Payment created successfully", data=response.json())
    return {
        "statusCode": 200,
        "message": "Payment created successfully",
        "response": response.json(),
        "data": response
    }



@app.get("/server/get_all_servers", status_code=status.HTTP_200_OK, tags=["SERVERS"])
@app.get("/server/get_all_servers/", status_code=status.HTTP_200_OK, tags=["SERVERS"])
def get_all_servers(db: db_dependency, token: str = Depends(get_token)):
    # To get logged in user
    try:
        payload = decode_jwt(token)
        token_expiry = payload.pop("expires")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Token!")


    #  [ CHECK TOKEN EXPIRY ]
    if token_expiry <= time.time():
        raise HTTPException(status_code=400, detail={"message": "Token Expired! Kindly login again!"})

    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.email == payload["email"]).first()
    if check_user is None:
        raise HTTPException(status_code=400, detail={"message": "Invalid Token! Kindly login again!"})


    get_all_servers = db.query(servers).all()

    return {
        "statusCode": 200,
        "data": get_all_servers
    }



@app.post("/server/get_config", status_code=status.HTTP_200_OK, tags=["SERVERS"])
@app.post("/server/get_config/", status_code=status.HTTP_200_OK, tags=["SERVERS"])
def get_config(data: get_config_pydantic_model, db: db_dependency, token: str = Depends(get_token)):
    # To get logged in user
    try:
        payload = decode_jwt(token)
        token_expiry = payload.pop("expires")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Token!")


    #  [ CHECK TOKEN EXPIRY ]
    if token_expiry <= time.time():
        raise HTTPException(status_code=400, detail={"message": "Token Expired! Kindly login again!"})

    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.email == payload["email"]).first()
    if check_user is None:
        raise HTTPException(status_code=400, detail={"message": "Invalid Token! Kindly login again!"})


    try:
        # Save the config, server_ip, and days_paid to user_config table
        user_config_obj = db.query(user_config).filter(
            user_config.email == payload["email"],
            user_config.server_ip == data.ip_address 
        ).first()

        if not user_config_obj:
            # If no record exists
            return {
                "statusCode": 404,
                "err": "Item Not Found!",
                "message": "no config found!"
            }

        try:
            with httpx.Client(timeout=Timeout(50.0)) as client:
                # set timeout to 50 seconds
                response_2 = client.get("http://{server_ip}/get_config/{config_name}/".format(
                    server_ip=data.ip_address, config_name=user_config_obj.config
                ), headers={"Content-Type": "application/json"})
        except httpx.TimeoutException as e:
            raise HTTPException(status_code=500, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
        
    except Exception as e:
        return {
            "statusCode": 400,
            "err": str(e)
        }
    return {
        "statusCode": 200,
        "message": "Config ID found",
        "config_id": user_config_obj.config,
        "days_left": user_config_obj.days_paid,
        "data": response_2.json()[0]["config_data"]  # the output seems to come out in a list containing the object
    }


@app.get("/server/get_user_plans", status_code=status.HTTP_200_OK, tags=["SERVERS"])
@app.get("/server/get_user_plans/", status_code=status.HTTP_200_OK, tags=["SERVERS"])
def get_user_current_plan(db: db_dependency, token: str = Depends(get_token)):
    """
    To get user's plans that aren't expired!
    """
    # To get logged in user
    try:
        payload = decode_jwt(token)
        token_expiry = payload.pop("expires")
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Token!")

    #  [ CHECK TOKEN EXPIRY ]
    if token_expiry <= time.time():
        raise HTTPException(status_code=400, detail={"message": "Token Expired! Kindly login again!"})

    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.email == payload["email"]).first()
    if check_user is None:
        raise HTTPException(status_code=400, detail={"message": "Invalid Token! Kindly login again!"})

    # user_plans_data = db.query(user_config).filter(user_config.email == check_user.email).all()
    # Join `user_config` with `servers` to get the `flag_url`
    user_plans_data = (
        db.query(
            user_config,
            servers.flag_url,
            servers.location,
        )
        .join(servers, user_config.server_ip == servers.server_ip)
        .filter(user_config.email == check_user.email)
        .all()
    )

    try:
        user_plan_list = []
        for i, flag_url, location in user_plans_data:
            user_plan_object = {
                "ip_address": "",
                "location": "",
                "config": "",
                "config_data": {},
                "days_left": 0,
                "flag_url": ""
            }
            user_plan_object["config"] = i.config
            user_plan_object["ip_address"] = i.server_ip
            user_plan_object["days_left"] = i.days_paid
            user_plan_object["flag_url"] = flag_url
            user_plan_object["location"] = location

            # to get  config details from the vpn server using config name
            try:
                with httpx.Client(timeout=Timeout(50.0)) as client:
                    # set timeout to 50 seconds
                    response_2 = client.get("http://{server_ip}/get_config/{config_name}/".format(
                        server_ip=i.server_ip, config_name=i.config
                     ), headers={"Content-Type": "application/json"})
            except httpx.TimeoutException as e:
                raise HTTPException(status_code=500, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

            user_plan_object["config_data"] = response_2.json()[0]["config_data"]

            user_plan_list.append(user_plan_object)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "statusCode": 200,
        "data": user_plan_list
    }

















@app.get("/populate_db_with_server_info", status_code=status.HTTP_200_OK, tags=["MISC"])
def populatedb(db: Session = Depends(get_db)):
    data = [
        {
            "server_ip": "167.99.220.220",
            "location": "Amsterdam, Netherlands",
            "price": "255.00",
            "flag_url": "https://flagcdn.com/w320/nl.png"
        },
        {
            "server_ip": "67.205.128.67",
            "location": "New York, USA",
            "price": "290.00",
            "flag_url": "https://flagcdn.com/w320/us.png"
        }
    ]

    # Iterate over the data and populate the db
    for server_data in data:
        # Check if server_ip already exists to avoid duplicates
        existing_server = db.query(servers).filter_by(server_ip=server_data["server_ip"]).first()
        if not existing_server:
            new_server = servers(
                server_ip=server_data["server_ip"],
                location=server_data["location"],
                price=server_data["price"],
                flag_url=server_data["flag_url"]
            )
            db.add(new_server)
    
    # Commit the changes to the database
    db.commit()

    return {"message": "Database populated successfully with server info"}
