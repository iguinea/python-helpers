# ========================================
# 4. MODELOS PYDANTIC (schemas.py)
# ========================================
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List
from enum import Enum

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=1)
    phone_number: Optional[str] = None
    
    @validator('password')
    def validate_password(cls, v):
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one digit')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(char.islower() for char in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(char in "!@#$%^&*()_+-=[]{}|;:,.<>?" for char in v):
            raise ValueError('Password must contain at least one special character')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    id_token: str
    token_type: str = "Bearer"
    expires_in: int

class EmailVerification(BaseModel):
    email: EmailStr
    code: str

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    email: EmailStr
    code: str
    new_password: str

class MFASetup(BaseModel):
    access_token: str

class MFAVerify(BaseModel):
    session: str
    code: str
    email: EmailStr

class RefreshToken(BaseModel):
    refresh_token: str
