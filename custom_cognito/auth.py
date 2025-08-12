# ========================================
# 6. JWT VALIDATION (auth.py)
# ========================================
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode
import json
import time
from typing import Optional, Dict, Any
import httpx
from functools import lru_cache

from .config import settings

security = HTTPBearer()

class JWTValidator:
    def __init__(self, settings):
        self.settings = settings
        self.jwks_url = f"https://cognito-idp.{settings.aws_region}.amazonaws.com/{settings.cognito_user_pool_id}/.well-known/jwks.json"
        self.jwks = None
        self.jwks_last_updated = 0
        
    @lru_cache(maxsize=1)
    async def _get_jwks(self):
        """Fetch and cache JWKS from Cognito"""
        current_time = time.time()
        
        # Refresh JWKS every hour
        if not self.jwks or (current_time - self.jwks_last_updated) > 3600:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.jwks_url)
                self.jwks = response.json()
                self.jwks_last_updated = current_time
                
        return self.jwks
    
    async def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate JWT token from Cognito"""
        try:
            # Get JWKS
            jwks = await self._get_jwks()
            
            # Get the kid from the token header
            headers = jwt.get_unverified_header(token)
            kid = headers['kid']
            
            # Find the key
            key = None
            for k in jwks['keys']:
                if k['kid'] == kid:
                    key = k
                    break
            
            if not key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Public key not found"
                )
            
            # Construct the public key
            public_key = jwk.construct(key)
            
            # Decode and validate the token
            payload = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=self.settings.cognito_app_client_id,
                issuer=f"https://cognito-idp.{self.settings.aws_region}.amazonaws.com/{self.settings.cognito_user_pool_id}"
            )
            
            # Check token expiration
            if payload['exp'] < time.time():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has expired"
                )
            
            return payload
            
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )

# Dependency for protected routes
_jwt_validator = None

def get_jwt_validator():
    global _jwt_validator
    if _jwt_validator is None:
        from .config import get_settings
        _jwt_validator = JWTValidator(get_settings())
    return _jwt_validator

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Get current user from JWT token"""
    token = credentials.credentials
    validator = get_jwt_validator()
    return await validator.validate_token(token)
