from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv
import os


load_dotenv()

SQLALCHEMY_DATABASE_URL1 =os.getenv("DEV_DATABASE_URL")
print(SQLALCHEMY_DATABASE_URL1)
engine = create_engine(SQLALCHEMY_DATABASE_URL1)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def api_response(status_code, data=None, message: str = None, total: int = 0, count: int = 0):
    response_data = {"data": data, "message": message, "status_code": status_code, "total": total, "count": count}
    filtered_response = {key: value for key, value in response_data.items() if value is not None or 0}
    return filtered_response

def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        print(f"Error in get_db: {e}") # for test
        db.rollback()
        raise
    finally:
        db.close()




# ENVIRONMENT = os.getenv("ENVIRONMENT")  # dev / prod

# DEV_DATABASE_URL = os.getenv("DEV_DATABASE_URL")
# PROD_DATABASE_URL = os.getenv("PROD_DATABASE_URL")


# dev_engine = create_engine(DEV_DATABASE_URL)
# prod_engine = create_engine(PROD_DATABASE_URL)

# Base = declarative_base()

# def get_db(db_env: str = None):
#     if not db_env:
#         db_env = ENVIRONMENT  

#     engine = prod_engine if db_env == "prod" else dev_engine
#     SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

#     db = SessionLocal()
#     try:
#         yield db
#     finally:
       # db.close()
