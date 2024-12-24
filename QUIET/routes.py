from QUIET import app
from fastapi import status, Depends, HTTPException, File, UploadFile, Form, Depends

from QUIET.models import (
    User, user_otp, servers,
    user_config, transaction
)
from QUIET.helper import (
    email_validator, generate_token,
    decode_jwt, get_token
)
from QUIET.pydantic_models import (
    signup_User, signin_User, update_user_model,
    paystack_payment_pydantic_model,
    verify_paystack_payment_pydantic_model,
    send_otp_model, verify_otp_model,
    change_password_model, get_config_pydantic_model,
    create_payment_pydantic_model
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
import json
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
        is_activated=False
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



@app.post("/payment/create", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
@app.post("/payment/create/", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
def create_payment(data: create_payment_pydantic_model, db: db_dependency, token: str = Depends(get_token)):
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

    token = None
    token_obj = {
        "email": check_user.email,
        "username": check_user.username
    }

    data = data.dict()

    # depending on ip, query db to get price per day
    get_server = db.query(servers).filter(servers.server_ip == data["server_ip"]).first()
    if get_server is None:
        raise HTTPException(status_code=404, detail="server not found!")

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

    trans_id_val = "vpn-{}".format(randint(100000000, 999999999))
    # store new transaction to db
    new_transaction = transaction(
        trans_id=trans_id_val,
        trans_status=False,
        server_ip=get_server.server_ip,
        location=get_server.location,
        days_paid=data["days_paid"],
        email=check_user.email,
        username=check_user.username,
        amount=str(amount_format),
        expired=False
    )
    db.add(new_transaction)
    db.commit()
    token = generate_token(token_obj)  # generate user token

    return {
        "statusCode": 200,
        "message": "Payment created successfully",
        "trans_id": trans_id_val,
        "token": token
    }


# [ PAYSTACK PAYMENT ]
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")
PAYSTACK_BASE_URL = "https://api.paystack.co/transaction"

@app.post("/payment/paystack", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
@app.post("/payment/paystack/", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
def create_payment_paystack(data: paystack_payment_pydantic_model, db: db_dependency):
    check_trans_id = db.query(transaction).filter(transaction.trans_id == data.trans_id).first()
    if check_trans_id is None:
        raise HTTPException(status_code=404, detail={"err": "transaction not found!"})

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    # depending on ip, query db to get price per day
    get_server = db.query(servers).filter(servers.server_ip == check_trans_id.server_ip).first()
    if get_server is None:
        raise HTTPException(status_code=500, detail="server not found!")

    # paystack payment payload
    payload = {
        "amount": str(int(check_trans_id.amount) * 100 * int(check_trans_id.days_paid)),
        "email": check_trans_id.email,
        "currency": "NGN",
        "callback_url": data.redirect_url
    }

    try:
        with httpx.Client(timeout=Timeout(60.0)) as client:
            # set timeout to 60 seconds
            response = client.post(f"{PAYSTACK_BASE_URL}/initialize", json=payload, headers=headers)
    except httpx.TimeoutException as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())

    response = (response.json())["data"]
    return {
        "statusCode": 200,
        "message": "Payment created successfully",
        "trans_id": check_trans_id.trans_id,
        "response": response
    }


# [ VERIFY PAYSTACK PAYMENT ]
@app.post("/payment/paystack/verify", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
@app.post("/payment/paystack/verify/", status_code=status.HTTP_200_OK, tags=["PAYMENT"])
def verify_paystack_payment(data: verify_paystack_payment_pydantic_model, db: db_dependency):
    trans_id = data.trans_id  # transaction id to validate payment on the backend
    check_transaction = db.query(transaction).filter(transaction.trans_id == trans_id).first()
    if check_transaction is None:
        raise HTTPException(status_code=404, detail={"err": "Transaction not found!"})

    username = check_transaction.username
    #  [ QUERY DB TO CONFIRM USER EXISTS ]
    check_user = db.query(User).filter(User.username == username).first()
    if check_user is None:
        raise HTTPException(status_code=404, detail={"err": "Account not found!"})

    token = None
    token_obj = {
        "email": check_user.email,
        "username": check_user.username
    }

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"
    }

    # verify paystack payment via transaction_id
    try:
        with httpx.Client(timeout=Timeout(60.0)) as client:
            # set timeout to 60 seconds
            response = client.get("{x}/verify/{y}".format(x=PAYSTACK_BASE_URL, y=data.transaction_id), headers=headers)
    except httpx.TimeoutException as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.json())
    # after successful verification, change the transaction status to success/true
    check_transaction.trans_status = True

    data_ = {}
    output_ = (response.json())["data"]
    output_customer = (response.json())["data"]["customer"]
    
    data_["id"] = output_["id"] or None
    data_["status"] = output_["status"] or None
    data_["reference"] = output_["reference"] or None
    data_["amount"] = output_["amount"] or None
    data_["currency"] = output_["currency"] or None
    data_["payment_type"] = output_["channel"] or None
    # data_["username"] = output_customer["name"] or None
    data_["email"] = output_customer["email"] or None

    if data_["status"] == "success":
        # check server type to determine url to eb called for new client
        check_server = db.query(servers).filter(servers.server_ip == check_transaction.server_ip).first()
        if check_server is None:
            raise HTTPException(status_code=404, detail={"err": "server not found!"})
            
        try:
            # with httpx.Client(timeout=Timeout(60.0)) as client:
                # set timeout to 60 seconds
                response_2 = None
                bin_val = None

                if check_server.server_type == "public":
                    with httpx.Client(timeout=Timeout(60.0)) as client:
                        response_2 = client.get("http://{server_ip}/create_peer/".format(
                            server_ip=check_transaction.server_ip
                        ), headers={"Content-Type": "application/json"})

                    bin_val = response_2.json()
                elif check_server.server_type == "private":
                    with httpx.Client(timeout=Timeout(60.0)) as client:
                        response_2 = client.get("https://wgvpn.luravpn.com:5000/wg/create_client?ipv4={server_ip}".format(
                            server_ip=check_transaction.server_ip
                        ), headers={"Content-Type": "application/json"})

                    while response_2.status_code != 200:
                        with httpx.Client(timeout=Timeout(60.0)) as client:
                            response_2 = client.get("https://wgvpn.luravpn.com:5000/wg/create_client?ipv4={server_ip}".format(
                                server_ip=check_transaction.server_ip
                            ), headers={"Content-Type": "application/json"})

                    bin_val = response_2.json()  # to confirm if request was sent to a valid ip_address
                    bin_val["data"].pop("server_id", None)  # Remove the "server_id" key if it exists
                    # client_id_value = bin_val.pop("client_id", None)
                    # bin_val["data"]["client_id"] = client_id_value
                    bin_val["message"] = "success"
        except httpx.TimeoutException as e:
            raise HTTPException(status_code=500, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail="invalid request! check server: {}".format(check_transaction.server_ip))
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
            user_config.server_ip == check_transaction.server_ip  # Match the server_ip as well
        ).first()

        if not user_config_obj:
            # If no record exists, create a new one
            user_config_obj = user_config(
                email=check_user.email,
                server_ip=check_transaction.server_ip,
                config=response_2.json()["data"]["client_id"],  # Assuming the config name is in the response
                days_paid=int(check_transaction.days_paid) + 1
            )
            db.add(user_config_obj)
        else:
            # If a record exists, replace the existing one
            # Delete from vpn server
            try:
                # with httpx.Client(timeout=Timeout(60.0)) as client:
                    if check_server.server_type == "public":
                        with httpx.Client(timeout=Timeout(60.0)) as client:
                            response_3 = client.get("http://{server_ip}/revoke_peer/{config_file}/".format(server_ip=check_transaction.server_ip,
                                             config_file=user_config_obj.config),
                                             headers={"Content-Type": "application/json"}
                                         )
                    elif check_server.server_type == "private":
                        with httpx.Client(timeout=Timeout(60.0)) as client:
                            response_3 = client.post("https://wgvpn.luravpn.com:5000/wg/revoke_client?ipv4={server_ip}".format(server_ip=check_transaction.server_ip),
                                             headers={"Content-Type": "application/json"}, data=json.dumps({"client_id": user_config_obj.config}))
                        while response_2.status_code != 200:
                            with httpx.Client(timeout=Timeout(60.0)) as client:
                                response_3 = client.post("https://wgvpn.luravpn.com:5000/wg/revoke_client?ipv4={server_ip}".format(server_ip=check_transaction.server_ip),
                                    headers={"Content-Type": "application/json"}, data=json.dumps({"client_id": user_config_obj.config}))
            except httpx.TimeoutException as e:
                pass
                # raise HTTPException(status_code=500, detail=str(e))

            # Replace in DB
            user_config_obj.server_ip = check_transaction.server_ip
            user_config_obj.config = response_2.json()["data"]["client_id"]  # Assuming the config name is in the response
            user_config_obj.days_paid += int(check_transaction.days_paid) + 1  # add up the remaining days with the new one
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Commit the changes
    check_transaction.trans_status = True
    db.commit()
    token = generate_token(token_obj)  # generate user token

    return {
        "statusCode": 200,
        "token": token,
        "days_paid": check_transaction.days_paid,
        "server_ip": check_transaction.server_ip,
        "server_location": check_transaction.location,
        "data": data_,
        "config_data": bin_val  # response_2.json()["data"],
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
            "item_no": 0,
            "server_ip": "5.39.254.59",
            "location": "London, UK",
            "price": "380.00",
            "flag_url": "https://flagcdn.com/w320/gb.png",
            "server_type": "private"
        },
        {
            "item_no": 1,
            "server_ip": "67.205.128.67",
            "location": "New York, USA",
            "price": "290.00",
            "flag_url": "https://flagcdn.com/w320/us.png",
            "server_type": "public"
        },
        {
            "item_no": 2,
            "server_ip": "134.122.107.207",
            "location": "London, UK",
            "price": "289.00",
            "flag_url": "https://flagcdn.com/w320/gb.png",
            "server_type": "public"
        },
        {
            "item_no": 3,
            "server_ip": "167.99.220.220",
            "location": "Amsterdam, NL",
            "price": "255.00",
            "flag_url": "https://flagcdn.com/w320/nl.png",
            "server_type": "public"
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
                flag_url=server_data["flag_url"],
                server_type=server_data["server_type"]
            )
            db.add(new_server)
    
    # Commit the changes to the database
    db.commit()

    return {"message": "Database populated successfully with server info"}
