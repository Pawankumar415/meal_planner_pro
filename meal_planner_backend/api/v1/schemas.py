from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime
from enum import Enum


class StatusEnum(str, Enum):
    active = "active"
    locked = "locked"
    inactive = "inactive"

class TenantTypeEnum(str, Enum):
    created = "created"
    supported = "supported"

class LoginTypeEnum(str, Enum):
    email = "email"
    google = "google"
    admin = "admin"

class LoginStatusEnum(str, Enum):
    success = "success"
    locked = "locked"
    failed = "failed"

class UserType(str, Enum):
    admin = "admin"
    user = "user"


class RegisterUser(BaseModel):
    user_name: str
    user_email: EmailStr
    phone: str
    user_password: str


    #confirm_password: str
    # user_type: UserType = UserType.user
    # status: StatusEnum

# class LoginUser(BaseModel):
#     email: EmailStr
#     password: str


# class OTPVerify(BaseModel):
#     email: EmailStr
#     otp_code: str



class LoginUser(BaseModel):
    email_or_phone: str
    password: str

class OTPVerify(BaseModel):
    email_or_phone: str
    otp_code: str


class RegisterUserResponse(BaseModel):
    message: str
    user_name: str
    user_email: EmailStr
    phone: str


class LoginResponse(BaseModel):
    message: str
    user_name: str
    user_email: EmailStr
    phone: str

class UserOut(RegisterUser):
    created_at: datetime
    class Config:
        orm_mode = True

# LoginAudit
class LoginAuditBase(BaseModel):
    user_id: str
    login_type: LoginTypeEnum
    status: LoginStatusEnum
    ip_address: str

class LoginAuditOut(LoginAuditBase):
    id: int
    login_time: datetime
    class Config:
        orm_mode = True


# PasswordHistory
class PasswordHistoryOut(BaseModel):
    history_id: int
    user_id: str
    password_hash: str
    changed_at: datetime
    class Config:
        orm_mode = True


# OTP
class OTPOut(BaseModel):
    otp_id: int
    user_id: str
    otp_code: str
    attempt_count: int
    is_verified: bool
    generated_at: datetime
    expired_at: datetime
    class Config:
        orm_mode = True


# SocialAuth
class SocialAuthOut(BaseModel):
    id: int
    user_id: str
    provider: str
    provider_user_id: str
    access_token: str
    refresh_token: str
    expiry_token: str
    class Config:
        orm_mode = True



from pydantic import BaseModel



class SendSMSOTP(BaseModel):
    phone_number: str

class VerifySMSOTPRequest(BaseModel):
    phone_number: str  # Changed from user_id to phone_number
    otp: str

class OTPVerify(BaseModel):
    email_or_phone: str
    otp_code: str



class ForgotPasswordRequest(BaseModel):
    email_or_phone: str


class ResetPasswordRequest(BaseModel):
    email_or_phone: str
    new_password: str
    confirm_new_password: str


class Otpverify(BaseModel):
    email: str
    otp_code: str



class UserOut(BaseModel):
    user_id: int
    username: str
    email: str
    phone_number: Optional[str]
    status: Optional[str]
    user_type: Optional[str]
    created_at: datetime
    is_verified: bool

    class Config:
        orm_mode = True


from datetime import date



from pydantic import BaseModel
from datetime import date
from typing import Optional
from fastapi import UploadFile

class ProfileBase(BaseModel):
    name: str
    email: str
    phone_number: str
    date_of_birth: date
    household_members: int
    state: str
    # image: Optional[str] = None  
    image: Optional[UploadFile] = None  

class ProfileCreate(ProfileBase):
    user_id: int

class ProfileUpdate(ProfileBase):
    user_id: int  # 
    name: Optional[str] = None
    email: Optional[str] = None
    phone_number: Optional[str] = None
    date_of_birth: Optional[date] = None
    household_members: Optional[int] = None
    state: Optional[str] = None
    image: Optional[UploadFile] = None

class ProfileResponse(ProfileBase):
    id: int
    user_id: int
    image: Optional[str] = None  
    class Config:
        orm_mode = True