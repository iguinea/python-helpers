"""
Custom Cognito Authentication Module

Provides FastAPI-based authentication using AWS Cognito with pycognito.
"""

from .config import Settings, settings
from .schemas import (
    UserRegister,
    UserLogin,
    TokenResponse,
    EmailVerification,
    PasswordReset,
    PasswordResetConfirm,
    MFASetup,
    MFAVerify,
    RefreshToken,
)
from .cognito_service import CognitoService
from .auth import JWTValidator, get_current_user

__all__ = [
    "Settings",
    "settings",
    "UserRegister",
    "UserLogin",
    "TokenResponse",
    "EmailVerification",
    "PasswordReset",
    "PasswordResetConfirm",
    "MFASetup",
    "MFAVerify",
    "RefreshToken",
    "CognitoService",
    "JWTValidator",
    "get_current_user",
]
