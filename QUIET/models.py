from sqlalchemy import (
    Boolean, Column, Integer,
    String, Text, Float, ForeignKey
)
from database import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(121), unique=True, index=True)  # unique email
    username = Column(String(101), unique=True, index=True)  # unique username
    password = Column(String(200))

    slug = Column(String(200))
    is_activated = Column(Boolean)

    days_paid = Column(Integer)
    server_ip = Column(String(20))
    server_location = Column(String(120))
    config_file = Column(String(20))


class user_otp(Base):
    # user otp credentials
    __tablename__ = "otp_table"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(101), unique=True, index=True)  # unique username
    otp_token = Column(String(10))
    otp_expiry = Column(String(20))
