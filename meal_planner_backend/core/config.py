import os
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    APP_NAME: str = "FastAPI OTP Auth"
    API_V1_STR: str = "/api/v1"
    API_V2_STR: str = "/api/v2"
    
    SECRET_KEY: str = os.getenv("SECRET_KEY", "development_secret_key")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    OTP_EXPIRE_MINUTES: int = 10
    
    DB_HOST: str = "localhost"
    DB_PORT: str = "5432"
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "postgres"
    DB_NAME: str = "fastapi_auth"
    
    SMTP_SERVER: str = "smtp.example.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = "noreply@example.com"
    SMTP_PASSWORD: str = "your_password"
    
    ENVIRONMENT: str = os.getenv("dev", "prod")
    
    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
    @property
    def SQLITE_DATABASE_URL(self) -> str:
        return "sqlite:///./app.db"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


class DevelopmentSettings(Settings):
    DEBUG: bool = True
    
    @property
    def DATABASE_URL(self) -> str:
        return self.SQLITE_DATABASE_URL


class ProductionSettings(Settings):
    DEBUG: bool = False
    
    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"


@lru_cache()
def get_settings():
    environment = os.getenv("ENVIRONMENT", "development")
    if environment.lower() == "production":
        return ProductionSettings()
    return DevelopmentSettings()


