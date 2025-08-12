# ========================================
# 7. API ROUTES (main.py)
# ========================================
from fastapi import FastAPI, HTTPException, Depends, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Dict, Any
import logging

# Import internal modules
from .config import get_settings
from .schemas import (
    UserRegister,
    UserLogin,
    TokenResponse,
    EmailVerification,
    PasswordReset,
    PasswordResetConfirm,
    MFAVerify
)
from .cognito_service import CognitoService
from .auth import get_current_user

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AWS Cognito Authentication API",
    description="Authentication service using AWS Cognito with pycognito",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[get_settings().frontend_url if get_settings() else "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services lazily
_cognito_service = None

def get_cognito_service():
    global _cognito_service
    if _cognito_service is None:
        from .config import get_settings
        _cognito_service = CognitoService(get_settings())
    return _cognito_service

# ========================================
# AUTHENTICATION ENDPOINTS
# ========================================


@app.post("/api/auth/register", response_model=Dict[str, Any])
async def register(user_data: UserRegister):
    """Register a new user"""
    try:
        result = await get_cognito_service().register_user(user_data)
        return {
            "message": "Registration successful. Please check your email for verification code.",
            "data": result,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")


@app.post("/api/auth/verify-email")
async def verify_email(verification: EmailVerification):
    """Verify user email with code"""
    try:
        await get_cognito_service().confirm_email(verification.email, verification.code)
        return {"message": "Email verified successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Email verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="Verification failed")


@app.post("/api/auth/login", response_model=TokenResponse)
async def login(user_credentials: UserLogin, response: Response):
    """Login user and return tokens"""
    try:
        tokens = await get_cognito_service().login(
            user_credentials.email, user_credentials.password
        )

        # Set refresh token as httpOnly cookie
        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=get_settings().environment == "production" if get_settings() else False,
            samesite="lax",
            max_age=get_settings().refresh_token_expire_days * 24 * 60 * 60 if get_settings() else 30 * 24 * 60 * 60,
        )

        return TokenResponse(**tokens)

    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")


@app.post("/api/auth/logout")
async def logout(response: Response, current_user: Dict = Depends(get_current_user)):
    """Logout user and revoke tokens"""
    try:
        # Get access token from authorization header
        # In real implementation, extract from request headers
        await get_cognito_service().logout(current_user.get("access_token", ""))

        # Clear refresh token cookie
        response.delete_cookie("refresh_token")

        return {"message": "Logged out successfully"}

    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        # Even if logout fails, clear cookies
        response.delete_cookie("refresh_token")
        return {"message": "Logged out"}


@app.post("/api/auth/refresh")
async def refresh_tokens(request: Request):
    """Refresh access token using refresh token from cookie"""
    try:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(status_code=401, detail="Refresh token not found")

        tokens = await get_cognito_service().refresh_tokens(refresh_token)

        return {
            "access_token": tokens["access_token"],
            "id_token": tokens["id_token"],
            "expires_in": tokens["expires_in"],
        }

    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(status_code=401, detail="Token refresh failed")


@app.post("/api/auth/forgot-password")
async def forgot_password(password_reset: PasswordReset):
    """Initiate password reset"""
    try:
        await get_cognito_service().initiate_password_reset(password_reset.email)
        return {"message": "If the email exists, a reset code has been sent"}
    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        # Don't reveal if email exists
        return {"message": "If the email exists, a reset code has been sent"}


@app.post("/api/auth/reset-password")
async def reset_password(reset_confirm: PasswordResetConfirm):
    """Confirm password reset with code"""
    try:
        await get_cognito_service().confirm_password_reset(
            reset_confirm.email, reset_confirm.code, reset_confirm.new_password
        )
        return {"message": "Password reset successful"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Password reset confirmation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Password reset failed")


# ========================================
# MFA ENDPOINTS
# ========================================


@app.post("/api/auth/mfa/setup")
async def setup_mfa(current_user: Dict = Depends(get_current_user)):
    """Setup MFA for authenticated user"""
    try:
        # Extract access token from current user context
        # In real implementation, get from authorization header
        mfa_setup = await get_cognito_service().setup_mfa(
            current_user.get("access_token", "")
        )
        return mfa_setup
    except Exception as e:
        logger.error(f"MFA setup error: {str(e)}")
        raise HTTPException(status_code=500, detail="MFA setup failed")


@app.post("/api/auth/mfa/verify")
async def verify_mfa(
    verification: MFAVerify, current_user: Dict = Depends(get_current_user)
):
    """Verify MFA setup"""
    try:
        result = await get_cognito_service().verify_mfa_setup(
            current_user.get("access_token", ""), verification.code
        )
        return {"message": "MFA enabled successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"MFA verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="MFA verification failed")


# ========================================
# PROTECTED ROUTES EXAMPLE
# ========================================


@app.get("/api/user/profile")
async def get_profile(current_user: Dict = Depends(get_current_user)):
    """Get current user profile"""
    return {
        "email": current_user.get("email"),
        "sub": current_user.get("sub"),
        "email_verified": current_user.get("email_verified"),
        "name": current_user.get("name"),
    }


# ========================================
# HEALTH CHECK
# ========================================


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "auth-api"}


# ========================================
# RUN THE APPLICATION
# ========================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=get_settings().environment == "development" if get_settings() else True,
    )
