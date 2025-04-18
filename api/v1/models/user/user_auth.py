import enum
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
from db.session import Base
import enum
from api.v1.schemas import StatusEnum, TenantTypeEnum,LoginTypeEnum, LoginStatusEnum

class User(Base):
    __tablename__ = 'user'
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255))
    email = Column(String(255), unique=True)
    phone_number = Column(String(255))
    password_hash = Column(String(255))
    status = Column(Enum(StatusEnum))
    user_type = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    is_verified = Column(Boolean, default=False)

    social_auths = relationship("SocialAuth", back_populates="user")

class OTP(Base):
    __tablename__ = 'otp'
    otp_id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=True)
    phone_number = Column(String(255), nullable=True)
    purpose= Column(String(30), nullable=True)
    otp_code = Column(String(10), nullable=True)
    attempt_count = Column(Integer, nullable=True)
    is_verified = Column(Boolean, nullable=True)
    generated_at = Column(DateTime, nullable=True)
    expired_at = Column(DateTime, nullable=True)

    






