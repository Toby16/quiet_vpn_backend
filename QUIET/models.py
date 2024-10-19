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

    days_paid = Column(Integer)
    server_ip = Column(String(20))
    server_location = Column(String(120))
    config_file = Column(String(20))

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
    __tablename__ = 'servers'  # Specify the table name here

    id = Column(Integer, primary_key=True, autoincrement=True)
    server_ip = Column(String(20), unique=True, index=True)
    location = Column(String(50))
    price = Column(String(10))


class user_config(Base):
    __tablename__ = 'user_configs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(121), ForeignKey('users.email'), unique=True, index=True)
    # email = Column(String(121), unique=True, index=True)
    server_ip = Column(String(20))
    config = Column(String(15))
    days_paid = Column(Integer())

    # Relationship back to User
    user = relationship('User', back_populates='configs')
