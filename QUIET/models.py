from sqlalchemy import (
    Boolean, Column, Integer,
    String, Text, Float, ForeignKey
)
from database import Base
from sqlalchemy.orm import relationship


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(121), unique=True, index=True)  # unique email
    username = Column(String(101), unique=True, index=True)  # unique username
    password = Column(String(200))

    slug = Column(String(200))
    is_activated = Column(Boolean)

    # Define relationship with user_config
    configs = relationship('user_config', back_populates='user', cascade="all, delete")


class user_otp(Base):
    # user otp credentials
    __tablename__ = "otp_table"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(101), unique=True, index=True)  # unique username
    otp_token = Column(String(10))
    otp_expiry = Column(String(20))


class servers(Base):
    __tablename__ = 'servers'

    id = Column(Integer, primary_key=True, autoincrement=True)
    server_ip = Column(String(20), unique=True, index=True)
    location = Column(Text)
    price = Column(String(10))
    flag_url = Column(Text)
    server_type = Column(Text)  # either 'private' or 'public'


class user_config(Base):
    __tablename__ = 'user_configs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(121), ForeignKey('users.email'), index=True)
    # email = Column(String(121), unique=True, index=True)
    server_ip = Column(String(20))
    config = Column(String(15))
    days_paid = Column(Integer())

    # Relationship back to User
    user = relationship('User', back_populates='configs')


class transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    trans_id = Column(String(16))  # transaction id
    trans_status = Column(Boolean)  # transaction status
    expired = Column(Boolean)  # default=Falsee, expired=True, failed/invalid=True
    server_ip = Column(String(20))
    location = Column(Text)
    days_paid = Column(Integer())
    amount = Column(String(10))
    email = Column(String(121))
    username = Column(String(101))
