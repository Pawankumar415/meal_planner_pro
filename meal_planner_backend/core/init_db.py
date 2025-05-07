from sqlalchemy.orm import Session
from core.config import get_settings
from db.session import Base, engine
from api.v1.models.user.user_auth import OTP, User
import logging

logger = logging.getLogger(__name__)
settings = get_settings()


def init_db(db: Session) -> None:
    if settings.ENVIRONMENT == "development":
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created in development mode")


    

