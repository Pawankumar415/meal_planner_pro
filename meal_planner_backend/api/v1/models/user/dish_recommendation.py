import enum
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Enum,Date,Text
from sqlalchemy.orm import relationship
from datetime import datetime
from db.session import Base
import enum
from api.v1.schemas import StatusEnum, TenantTypeEnum,LoginTypeEnum, LoginStatusEnum,StatusEnum


class UserInteraction(Base):
    __tablename__ = "user_interactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('user.user_id'))
    session_id = Column(String(50))
    user_input = Column(Text)
    response = Column(Text)
      
    user = relationship("User", back_populates="interactions") #
