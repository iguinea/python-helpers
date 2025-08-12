# ========================================
# 3. CONFIGURACIÓN (config.py)
# ========================================
from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    # AWS Cognito
    aws_region: str = "eu-west-1"
    aws_profile: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    cognito_user_pool_id: str
    cognito_app_client_id: str
    cognito_app_client_secret: Optional[str] = None

    # Application
    frontend_url: str = "http://localhost:3000"
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret_key: str
    environment: str = "development"

    # Security
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 30

    class Config:
        env_file = ".env"
        case_sensitive = False


# Lazy initialization to avoid loading during imports
_settings = None


def get_settings():
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


# For backward compatibility - only load if environment variables are present
if os.environ.get("COGNITO_USER_POOL_ID"):
    settings = Settings()
else:
    settings = None
