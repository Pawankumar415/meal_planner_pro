from fastapi import APIRouter, Depends, HTTPException, status, Query, File, UploadFile
from sqlalchemy.orm import Session
from db.session import get_db
from api.v1.models.user.user_auth import User, Profile
from api.v1.schemas import ProfileResponse, ProfileCreate, ProfileUpdate
from typing import Optional
import shutil  # 

router = APIRouter()

# Create Profile with Image Upload
@router.post("/profiles/", response_model=ProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_profile(
    profile: ProfileCreate = Depends(),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    """
    Create a new profile with optional image upload.
    """
    db_user = db.query(User).filter(User.user_id == profile.user_id).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")

    # Check if a profile already exists for this user
    existing_profile = db.query(Profile).filter(Profile.user_id == profile.user_id).first()
    if existing_profile:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="A profile already exists for this user. Use update endpoint.")

    profile_data = profile.dict()
    if image:
        file_path = f"static/images/{image.filename}" 
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        profile_data["image"] = file_path  # டேட்டாபேஸ்ல ஃபைல் பாத்தை ஸ்டோர் பண்ணு

    db_profile = Profile(**profile_data)
    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)
    return db_profile

# Update Profile with Optional Image Upload
@router.put("/profiles/", response_model=ProfileResponse)
async def update_profile(
    profile_update: ProfileUpdate = Depends(),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    """
    Update an existing profile with optional image upload.
    """
    db_profile = db.query(Profile).filter(Profile.user_id == profile_update.user_id).first()
    if not db_profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found for this user")

    profile_data = profile_update.dict(exclude_unset=True)
    if image:
        file_path = f"static/images/{image.filename}"  # ஃபைலை சேவ் பண்ணுற பாத்
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        profile_data["image"] = file_path  # டேட்டாபேஸ்ல புது ஃபைல் பாத்தை அப்டேட் பண்ணு

    for field, value in profile_data.items():
        setattr(db_profile, field, value)

    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)
    return db_profile

# Get Profile by User ID (no change needed here)
@router.get("/profiles/", response_model=Optional[ProfileResponse])
def get_profile_by_user_id(user_id: int = Query(..., description="User ID to retrieve profile"), db: Session = Depends(get_db)):
    """
    Retrieve a profile by user ID.
    """
    db_profile = db.query(Profile).filter(Profile.user_id == user_id).first()
    if db_profile:
        return db_profile
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Profile not found for user ID: {user_id}")