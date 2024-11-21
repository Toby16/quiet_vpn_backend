from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv
import os

load_dotenv()


URL_DATABASE = os.getenv("DATABASE_URL")
engine = create_engine(
                      URL_DATABASE,
                      pool_recycle=3600,  # Recycle connections every hour
                      pool_pre_ping=True  # Test connections before using them
                      )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
