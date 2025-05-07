

# pasted by bhavan kumar


from datetime import datetime, time, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from api.v1.schemas import LoginUser, RegisterUser,OTPVerify,ForgotPasswordRequest,ResetPasswordRequest,Otpverify,UserOut,StatusEnum
from auth.auth_handler import signJWT
from core.Email_config import send_otp_email,send_email
from db.session import get_db
from api.v1.models.user.user_auth import OTP, User
import random
import re
import bcrypt
from sqlalchemy.exc import SQLAlchemyError
import pytz
from twilio.rest import Client
import logging
import os
from sqlalchemy.sql.expression import desc

router = APIRouter()

utc_now = pytz.utc.localize(datetime.utcnow())
ist_now = utc_now.astimezone(pytz.timezone('Asia/Kolkata'))

def generate_otp():
    return str(random.randint(1000, 9999))

def validate_email(email):
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(email_pattern, email)
    
def validate_password(password):
        return len(password) >= 8
    
def validate_phone_number(phone_number):
    phone_pattern = r"^\+91\d{10}$"
    return re.match(phone_pattern, phone_number)


TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


@router.post("/v1/auth/pre-register/email_verify", response_model=None)
async def pre_register(email: str, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="This email is already registered and verified.")
        elif existing_user and not existing_user.is_verified:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This email is already registered but not verified. Please proceed to login or request a new OTP.")

        if not validate_email(email):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid email format. Please enter a valid email address.")

        otp = generate_otp()
        now = datetime.utcnow()
        expiry = now + timedelta(minutes=5)

        otp_entry = OTP(
            email=email,
            purpose="register",  
            otp_code=otp,
            attempt_count=0,
            is_verified=False,
            generated_at=now,
            expired_at=expiry
        )

        db.add(otp_entry)
        db.commit()

        try:
            await send_otp_email(email, otp)
            return {"msg": "OTP sent to your email for verification."}
        except Exception as e:
            logging.error(f"Error sending OTP email: {e}")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to send OTP email service. Please try again later.")
        
    except HTTPException as e:
        print(f"error: {e}")
        raise e
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error occurred while processing email verification.{e}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred during email verification. Please try again.{e}")

    

      
@router.post("/v1/auth/pre-register/verify-otp")
async def verify_otp(data:Otpverify, db: Session = Depends(get_db)):
    try:
        otp_entry = db.query(OTP).filter(OTP.email == data.email).order_by(OTP.generated_at.desc()).first()

        if not otp_entry:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OTP not found for this email.")
        
        if otp_entry.purpose != "register":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This OTP is not for registration.")

        if otp_entry.expired_at < datetime.utcnow():
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="OTP has expired.")

        if otp_entry.otp_code != data.otp_code:
            otp_entry.attempt_count = (otp_entry.attempt_count or 0) + 1
            db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP. Please try again.")

        otp_entry.is_verified = True
        otp_entry.attempt_count = otp_entry.attempt_count or 0
        db.commit()

        return {"msg": "OTP verified and email is now verified. You can now proceed with registration."}

    except HTTPException as e:
        raise e
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error occurred while verifying OTP.")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred during OTP verification. Please try again.")
    

   
@router.post("/v1/auth/register", response_model=None)
def register(user: RegisterUser, db: Session = Depends(get_db)):
    try:
        otp_entry = db.query(OTP).filter(OTP.email == user.user_email, OTP.is_verified == True).first()
        if not otp_entry:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email verification is required before registration.")

        # if user.user_password != user.confirm_password:
        #     raise HTTPException(status_code=400, detail="Passwords do not match")

        if not validate_email(user.user_email):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid email format")

        
        # if not validate_phone_number(user.phone):
        #     raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid phone number. It must be 10 digits and include the country code (e.g., +91 for India).")

        if not validate_password(user.user_password):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters long")

        existing_user = db.query(User).filter(User.email == user.user_email).first()
        if existing_user and existing_user.is_verified:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

        hashed_password = bcrypt.hashpw(user.user_password.encode(), bcrypt.gensalt()).decode()

        new_user = User(
            username=user.user_name,
            email=user.user_email,
            phone_number=user.phone,
            password_hash=hashed_password,
            status=StatusEnum.active,
            created_at=datetime.utcnow(),
            is_verified=True 
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return {"message": "Registration successful","new_user": new_user.email,}

    except HTTPException as e:
        raise e
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Database error occurred.")
    except Exception as e:
        print(f"error occured : {e}")
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected error occurred please try again")




@router.post("/v1/auth/login")
async def login(user_credentials: LoginUser, db: Session = Depends(get_db)):
    try:
        user_db = None
        login_id = user_credentials.email_or_phone
        if validate_email(login_id):
            user_db = db.query(User).filter(User.email == login_id).first()
        elif validate_phone_number(login_id):
            user_db = db.query(User).filter(User.phone_number == login_id).first()
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid email or phone number format. Phone number must be 10 digits and can include the country code (e.g., +91 for India).")

        if not user_db:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist. Please register.")

        if not bcrypt.checkpw(user_credentials.password.encode('utf-8'), user_db.password_hash.encode('utf-8')):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

        otp = generate_otp()
        now = datetime.utcnow()
        expiry = now + timedelta(minutes=5)

        otp_entry = OTP(
            email=user_db.email if validate_email(login_id) else None,
            phone_number=user_db.phone_number if validate_phone_number(login_id) else None,
            purpose="login",
            otp_code=otp,
            attempt_count=0,
            is_verified=False,
            generated_at=now,
            expired_at=expiry
        )

        db.add(otp_entry)
        db.commit()

        if validate_email(login_id):
            await send_otp_email(user_db.email, otp)
            return {"message": "OTP sent to your email"}
        elif validate_phone_number(login_id):
            try:
                message = client.messages.create(
                    to=user_db.phone_number,
                    from_=TWILIO_PHONE_NUMBER,
                    body=f"Your OTP for login is: {otp}"
                )
                print(f"SMS sent with SID: {message.sid}")
                return {"message": "OTP sent to your phone number"}
            except Exception as e:
                logging.error(f"Error sending SMS: {e}")
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Failed to send OTP via SMS. Please try again later.")

    except HTTPException as e:
        raise e
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error occurred during login.")
    except Exception as e:
        print(e,"********************************")
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred during login. Please try again.")
    


#################################################################################################

@router.post("/v1/auth/verify_login_otp", status_code=status.HTTP_200_OK)
def verify_otp(data: OTPVerify, db: Session = Depends(get_db)):
    try:
        user_db = None
        login_id = data.email_or_phone
        if validate_email(login_id):
            user_db = db.query(User).filter(User.email == login_id).first()
        elif validate_phone_number(login_id):
            user_db = db.query(User).filter(User.phone_number == login_id).first()
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid email or phone number format. Phone number must be 10 digits and can include the country code (e.g., +91 for India).")

        if not user_db:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        otp_query = db.query(OTP).filter(
            OTP.purpose == "login",
            OTP.is_verified == False
        ).order_by(OTP.generated_at.desc())

        if validate_email(login_id):
            otp_query = otp_query.filter(OTP.email == user_db.email)
        elif validate_phone_number(login_id):
            otp_query = otp_query.filter(OTP.phone_number == user_db.phone_number)
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid email or phone number format. Phone number must be 10 digits and can include the country code (e.g., +91 for India).")

        otp_entry = otp_query.first()

        if not otp_entry:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active OTP found for this user.")

        if datetime.utcnow() > otp_entry.expired_at:
            otp_entry.otp_code = None
            db.commit()
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="OTP has expired.")
        if otp_entry.otp_code != data.otp_code:
            otp_entry.attempt_count = (otp_entry.attempt_count or 0) + 1
            db.commit()
            if otp_entry.attempt_count >= 3:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many failed OTP attempts. Account temporarily locked. Please try again later.")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP.")

        # OTP verified
        otp_entry.is_verified = True
        db.commit()

        token, exp = signJWT(user_db.user_id, user_db.user_type)

        return {
            "msg": "OTP verified successfully, login successful",
            "username": user_db.username,
            "email": user_db.email,
            "phone_number": user_db.phone_number,
            "user_type": user_db.user_type,
            "is_verified": user_db.is_verified,
            "token": token,
            "expires_at": exp,
            "created_at": user_db.created_at,
        }

    except HTTPException as e:
        raise e
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error occurred during OTP verification.")
    except Exception as e:
        print(f"Verify OTP Error: {e} ********************************")
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred during OTP verification. Please try again.")



    
@router.get("/v1/all_users", response_model=List[UserOut])
def get_all_users(db: Session = Depends(get_db)):
    try:
        users = db.query(User).all()
        return users 
    except HTTPException as e:
        raise e
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error occurred while fetching users.")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred while fetching users. Please try again.")











# @router.get("/v1/auth/resend-otp/{email}")
# async def resend_otp(email: str, db: Session = Depends(get_db)):
#     try:
#         user = db.query(User).filter(User.email == email).first()
#         if not user:
#             raise HTTPException(status_code=404, detail="User not found")

#         db.query(OTP).filter(OTP.email == user.email, OTP.is_verified == False).update({OTP.otp_code: None})
#         db.commit()

#         otp_code = generate_otp()
#         now = datetime.utcnow()

#         db.add(OTP(
#             user_id=user.user_id,
#             otp_code=otp_code,
#             attempt_count=0,
#             is_verified=False,
#             generated_at=now,
#             expired_at=now + timedelta(minutes=5)
#         ))
#         db.commit()

#         await send_otp_email(email, otp_code)

#         return {"msg": "OTP resent successfully"}

#     except HTTPException as e:
#         raise e
#     except SQLAlchemyError:
#         db.rollback()
#         raise HTTPException(status_code=404, detail="Database error occurred.")
#     except Exception as e:
#         db.rollback()
#         raise HTTPException(status_code=500, detail=f"Unexpected error occurred please try again")





#############################################################################
# forget password endpoints





@router.post("/v1/auth/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    login_id = request.email_or_phone
    user = None
    if validate_email(login_id):
        user = db.query(User).filter(User.email == login_id).first()
    elif validate_phone_number(login_id):
        user = db.query(User).filter(User.phone_number == login_id).first()
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or phone number format")

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    otp = generate_otp()
    now = datetime.utcnow()
    expiry = now + timedelta(minutes=5)

    otp_entry = OTP(
        email=user.email if validate_email(login_id) else None,
        phone_number=user.phone_number if validate_phone_number(login_id) else None,
        purpose="forgot_password",
        otp_code=otp,
        attempt_count=0,
        is_verified=False,
        generated_at=now,
        expired_at=expiry
    )

    db.add(otp_entry)
    db.commit()

    if validate_email(login_id):
        subject = "Password Reset OTP"
        body = f"""
        <h3>{subject}</h3>
        <p>Your OTP for password reset is: {otp}. This OTP is valid for 5 minutes.</p>
        <p>If you did not request this, please ignore this message.</p>
        <br>
        <p>Best regards,</p>
        <p>Your Team</p>
        """
        try:
            await send_email(subject=subject, email_to=user.email, body=body)
            return {"message": "OTP sent to your email for password reset"}
        except Exception as e:
            logging.error(f"Error sending email for forgot password: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send OTP email")
    elif validate_phone_number(login_id):
        try:
            message = client.messages.create(
                to=user.phone_number,
                from_=TWILIO_PHONE_NUMBER,
                body=f"Your OTP for password reset is: {otp}. This OTP is valid for 5 minutes."
            )
            print(f"SMS sent with SID: {message.sid}")
            return {"message": "OTP sent to your phone number for password reset"}
        except Exception as e:
            #logging.error(f"Error sending SMS for forgot password: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to send OTP via SMS")

    return {"message": "OTP sent successfully"}






@router.post("/v1/auth/forgot-password/verify-otp", status_code=status.HTTP_200_OK)
def verify_forgot_password_otp(data: OTPVerify, db: Session = Depends(get_db)):
    login_id = data.email_or_phone
    user = None
    if validate_email(login_id):
        user = db.query(User).filter(User.email == login_id).first()
    elif validate_phone_number(login_id):
        user = db.query(User).filter(User.phone_number == login_id).first()
    else:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid email or phone number format. Please enter a valid email or phone number (e.g., +91 for india).")

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found with this email or phone number.")

    otp_entry = db.query(OTP).filter(
        OTP.email == user.email if validate_email(login_id) else OTP.phone_number == user.phone_number,
        OTP.purpose == "forgot_password",
        OTP.is_verified == False
    ).order_by(desc(OTP.generated_at)).first()

    if not otp_entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active OTP found for password reset")

    if datetime.utcnow() > otp_entry.expired_at:
        otp_entry.otp_code = None
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP has expired")

    if otp_entry.otp_code != data.otp_code:
        otp_entry.attempt_count = (otp_entry.attempt_count or 0) + 1
        db.commit()
        if otp_entry.attempt_count >= 3:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Too many failed attempts. OTP locked for password reset.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")

    otp_entry.is_verified = True
    db.commit()

    # Here you can generate a temporary token and return it to the user
    # for resetting the password in the next step.
    return {"message": "OTP verified successfully. You can now reset your password."}




@router.post("/v1/auth/forgot-password/reset-password", status_code=status.HTTP_200_OK)
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    login_id = request.email_or_phone
    user = db.query(User).filter(User.email == login_id).first() or db.query(User).filter(User.phone_number == login_id).first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    otp_entry = db.query(OTP).filter(
        (OTP.email == user.email if hasattr(user, 'email') and user.email == login_id else OTP.phone_number == login_id),
        OTP.purpose == "forgot_password",
        OTP.is_verified == True
    ).order_by(desc(OTP.generated_at)).first()

    if not otp_entry:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password reset is not allowed. Please complete the forgot password process.")

    if request.new_password != request.confirm_new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")

    hashed_password = bcrypt.hashpw(request.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user.password_hash = hashed_password
    db.commit()

    otp_entry.is_verified = False
    db.commit()

    return {"message": "Password reset successfully. You can now log in with your new password."}