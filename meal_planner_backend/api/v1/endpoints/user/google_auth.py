import os
from fastapi import APIRouter, Request, Depends, HTTPException,status
from fastapi.responses import RedirectResponse
from google_auth_oauthlib.flow import Flow
import requests
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from db.session import get_db
from api.v1.models.user.user_auth import User
from datetime import datetime
from auth.auth_handler import signJWT
from dotenv import load_dotenv
import logging
import json

load_dotenv()


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

SCOPES = ["https://www.googleapis.com/auth/userinfo.email", 
          "https://www.googleapis.com/auth/userinfo.profile", 
          "openid"]

router = APIRouter()

client_secrets = {
    "web": {
        "client_id": GOOGLE_CLIENT_ID,
        "project_id": os.getenv("GOOGLE_PROJECT_ID", ""),  
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uris": [GOOGLE_REDIRECT_URI],
    }
}

@router.get("/v1/auth/google/login")
async def google_login():
    try:
        flow = Flow.from_client_config(
            client_secrets,
            scopes=SCOPES,
            redirect_uri=GOOGLE_REDIRECT_URI
        )

        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent"  
        )

        logger.info(f"Redirecting to Google OAuth URL: {authorization_url}")
        return RedirectResponse(authorization_url)
    except Exception as e:
        logger.error(f"Error initiating Google OAuth flow: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to initiate Google login. Please try again.")




@router.get("/v1/auth/google/callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    try:
        code = request.query_params.get("code")
        if not code:
            logger.error("No authorization code received from Google")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization code was not provided by Google. Authentication failed.")

        flow = Flow.from_client_config(
            client_secrets,
            scopes=SCOPES,
            redirect_uri=GOOGLE_REDIRECT_URI
        )
        try:
            flow.fetch_token(code=code)
        except Exception as e:
            logger.error(f"Failed to fetch token from Google: {str(e)}", exc_info=True)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Failed to authenticate with Google. Invalid authorization code.")
        
        credentials = flow.credentials

        userinfo_response = requests.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {credentials.token}"}
        )

        if userinfo_response.status_code != 200:
            logger.error(f"Failed to get user info from Google: {userinfo_response.text}")
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to retrieve user information from Google. Please try again.")

        user_info = userinfo_response.json()

        email = user_info.get("email")
        if not email:
            logger.error("Email not provided by Google")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email was not provided by Google. Authentication failed.")

        username = user_info.get("name", "GoogleUser")
        is_email_verified = user_info.get("email_verified", False)
        google_user_id = user_info.get("sub")

        existing_user = db.query(User).filter(User.email == email).first()

        if existing_user:
            user = existing_user
            logger.info(f"User {email} logged in via Google OAuth")
        else:
            logger.info(f"Creating new user from Google OAuth: {email}")
            new_user = User(
                username=username,
                email=email,
                phone_number="0000000000",
                password_hash="GOOGLE_AUTH",
                status="active",
                user_type="user",
                created_at=datetime.utcnow(),
                is_verified=True if is_email_verified else False
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)  # Get the generated user_id
            user = new_user

        try:
            from api.v1.models.user.google_auth import SocialAuth
            social_auth = SocialAuth(
                user_id=user.user_id,
                email=email,
                provider="google",
                provider_user_id=google_user_id,
                created_at=datetime.utcnow()
            )
            db.add(social_auth)
            db.commit()
            logger.info(f"Added Google social auth record for user {user.user_id}")
        except ImportError:
            logger.warning("SocialAuth model not available, skipping social auth record")
        except Exception as e:
            logger.error(f"Error creating social auth record: {str(e)}", exc_info=True)
            db.rollback()
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create social authentication record.")

        token, exp = signJWT(user.user_id, user.user_type)

        return {
            "msg": "Google login successful",
            "token": token,
            "username": user.username,
            "email": user.email,
            "user_type": user.user_type,
            "created_at": user.created_at,
            "expires_at": exp,
        }
    except HTTPException as e:
        raise e
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error occurred during Google authentication.")
    except Exception as e:
        logger.error(f"Unexpected error in Google callback: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred during Google authentication. Please try again.")
