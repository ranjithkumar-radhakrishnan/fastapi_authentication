import os
import urllib.parse

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.models.user import Base

base_path = os.path.dirname(os.path.abspath(__file__))
new_base_path = os.path.dirname(os.path.dirname(base_path))
dotenv_path = os.path.join(new_base_path, '.env')


load_dotenv(dotenv_path)

USER = os.getenv("DB_USER")
PASSWORD = os.getenv("DB_PASSWORD")
HOST = os.getenv("DB_HOST")
PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

encoded_password = urllib.parse.quote(PASSWORD)
DB_URL = f"postgresql://{USER}:{encoded_password}@{HOST}:{PORT}/{DB_NAME}"

engine = create_engine(DB_URL)
Base.metadata.create_all(bind=engine)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# class Database:
#     def __init__(self, db_url: str):
#         self.db_url = db_url
#         self.engine = create_engine(self.db_url)
#         self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
#
#     def get_db(self):
#         db = self.SessionLocal()
#         try:
#             yield db
#         finally:
#             db.close()
#
#
# Base = declarative_base()
#
# db_instance = Database(DB_URL)
# Base.metadata.create_all(bind=db_instance.engine)
