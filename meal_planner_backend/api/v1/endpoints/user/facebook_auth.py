import os
from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
import requests
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from db.session import get_db
from api.v1.models.user.user_auth import User
from datetime import datetime
from auth.auth_handler import signJWT
from dotenv import load_dotenv
import logging
from api.v1.models.user.google_auth import SocialAuth

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FACEBOOK_APP_ID = os.getenv("FACEBOOK_APP_ID")
FACEBOOK_APP_SECRET = os.getenv("FACEBOOK_APP_SECRET")
FACEBOOK_REDIRECT_URI = os.getenv("FACEBOOK_REDIRECT_URI")

FACEBOOK_GRAPH_URL = "https://graph.facebook.com/v18.0"  # Use the latest API version

router = APIRouter()

@router.get("/v1/auth/facebook/login")
async def facebook_login():
    facebook_auth_url = f"https://www.facebook.com/v18.0/dialog/oauth?client_id={FACEBOOK_APP_ID}&redirect_uri={FACEBOOK_REDIRECT_URI}&scope=email,public_profile"
    logger.info(f"Redirecting to Facebook OAuth URL: {facebook_auth_url}")
    return RedirectResponse(facebook_auth_url)

@router.get("/v1/auth/facebook/callback")
async def facebook_callback(request: Request, db: Session = Depends(get_db)):
    try:
        code = request.query_params.get("code")
        if not code:
            logger.error("No authorization code received from Facebook")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization code was not provided by Facebook. Authentication failed.")

        # Exchange authorization code for access token
        token_url = f"{FACEBOOK_GRAPH_URL}/oauth/access_token"
        token_params = {
            "client_id": FACEBOOK_APP_ID,
            "client_secret": FACEBOOK_APP_SECRET,
            "code": code,
            "redirect_uri": FACEBOOK_REDIRECT_URI
        }
        token_response = requests.post(token_url, params=token_params)
        token_response.raise_for_status()
        access_token_data = token_response.json()
        access_token = access_token_data.get("access_token")

        if not access_token:
            logger.error(f"Failed to get access token from Facebook: {token_response.text}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Failed to authenticate with Facebook. Invalid authorization code.")

        # Get user info from Facebook
        user_info_url = f"{FACEBOOK_GRAPH_URL}/me"
        user_info_params = {
            "fields": "id,name,email",
            "access_token": access_token
        }
        user_info_response = requests.get(user_info_url, params=user_info_params)
        user_info_response.raise_for_status()
        user_info = user_info_response.json()

        facebook_user_id = user_info.get("id")
        email = user_info.get("email")
        username = user_info.get("name", "FacebookUser")

        if not email:
            logger.error("Email not provided by Facebook")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email was not provided by Facebook. Authentication failed.")

        existing_user = db.query(User).filter(User.email == email).first()

        if existing_user:
            user = existing_user
            logger.info(f"User {email} logged in via Facebook OAuth")
        else:
            logger.info(f"Creating new user from Facebook OAuth: {email}")
            new_user = User(
                username=username,
                email=email,
                phone_number="0000000000",
                password_hash="FACEBOOK_AUTH",
                status="active",
                user_type="user",
                created_at=datetime.utcnow(),
                is_verified=True  # Facebook usually provides verified emails
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)
            user = new_user

        # Check if social auth record already exists for this Facebook user
        existing_social_auth = db.query(SocialAuth).filter(
            SocialAuth.provider == "facebook",
            SocialAuth.provider_user_id == facebook_user_id
        ).first()

        if not existing_social_auth:
            try:
                social_auth = SocialAuth(
                    user_id=user.user_id,
                    email=email,
                    provider="facebook",
                    provider_user_id=facebook_user_id,
                    access_token=access_token,
                    created_at=datetime.utcnow()
                )
                db.add(social_auth)
                db.commit()
                logger.info(f"Added Facebook social auth record for user {user.user_id}")
            except SQLAlchemyError as e:
                logger.error(f"Error creating social auth record: {str(e)}", exc_info=True)
                db.rollback()
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create social authentication record.")
        else:
            logger.info(f"Social auth record already exists for Facebook user ID: {facebook_user_id}")

        token, exp = signJWT(user.user_id, user.user_type)

        return {
            "msg": "Facebook login successful",
            "token": token,
            "username": user.username,
            "email": user.email,
            "user_type": user.user_type,
            "created_at": user.created_at,
            "expires_at": exp,
        }
    except HTTPException as e:
        raise e
    except requests.exceptions.RequestException as e:
        logger.error(f"Error communicating with Facebook: {str(e)}")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to communicate with Facebook. Please try again.")
    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Database error during Facebook authentication: {str(e)}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error occurred during Facebook authentication.")
    except Exception as e:
        logger.error(f"Unexpected error in Facebook callback: {str(e)}", exc_info=True)
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred during Facebook authentication. Please try again.")