import enum
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
from db.session import Base
import enum
from api.v1.schemas import StatusEnum, TenantTypeEnum,LoginTypeEnum, LoginStatusEnum



class SocialAuth(Base):
    __tablename__ = "social_auth"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("user.user_id"))
    email = Column(String(255))
    provider = Column(String(255))
    provider_user_id = Column(String(255))
    access_token =Column(String(1024))
    created_at = Column(DateTime, default=datetime.utcnow)
    refresh_token = Column(String(255))
    expiry_token = Column(String(255))

    user = relationship("User", back_populates="social_auths")


