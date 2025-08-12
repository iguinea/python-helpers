"""
Tests for Pydantic schemas.
"""
import pytest
from pydantic import ValidationError

from custom_cognito.schemas import (
    UserRegister,
    UserLogin,
    EmailVerification,
    PasswordReset,
    PasswordResetConfirm,
    MFAVerify,
)

class TestSchemas:
    """Test cases for Pydantic schemas."""
    
    def test_user_register_valid(self):
        """Test valid user registration data."""
        data = {
            "email": "test@example.com",
            "password": "TestPass123!",
            "full_name": "Test User",
            "phone_number": "+1234567890"
        }
        
        user = UserRegister(**data)
        assert user.email == data["email"]
        assert user.password == data["password"]
        assert user.full_name == data["full_name"]
        assert user.phone_number == data["phone_number"]
    
    def test_user_register_invalid_email(self):
        """Test user registration with invalid email."""
        data = {
            "email": "invalid-email",
            "password": "TestPass123!",
            "full_name": "Test User"
        }
        
        with pytest.raises(ValidationError) as exc_info:
            UserRegister(**data)
        
        errors = exc_info.value.errors()
        assert any(error["loc"] == ("email",) for error in errors)
    
    def test_user_register_weak_password(self):
        """Test user registration with weak password."""
        # Test password without digit
        data = {
            "email": "test@example.com",
            "password": "TestPass!",
            "full_name": "Test User"
        }
        
        with pytest.raises(ValidationError, match="at least one digit"):
            UserRegister(**data)
        
        # Test password without uppercase
        data["password"] = "testpass123!"
        with pytest.raises(ValidationError, match="at least one uppercase"):
            UserRegister(**data)
        
        # Test password without lowercase
        data["password"] = "TESTPASS123!"
        with pytest.raises(ValidationError, match="at least one lowercase"):
            UserRegister(**data)
        
        # Test password without special character
        data["password"] = "TestPass123"
        with pytest.raises(ValidationError, match="at least one special character"):
            UserRegister(**data)
        
        # Test password too short
        data["password"] = "Tp1!"
        with pytest.raises(ValidationError):
            UserRegister(**data)
    
    def test_user_login_valid(self):
        """Test valid user login data."""
        data = {
            "email": "test@example.com",
            "password": "TestPass123!"
        }
        
        login = UserLogin(**data)
        assert login.email == data["email"]
        assert login.password == data["password"]
    
    def test_email_verification_valid(self):
        """Test valid email verification data."""
        data = {
            "email": "test@example.com",
            "code": "123456"
        }
        
        verification = EmailVerification(**data)
        assert verification.email == data["email"]
        assert verification.code == data["code"]
    
    def test_password_reset_valid(self):
        """Test valid password reset data."""
        data = {"email": "test@example.com"}
        
        reset = PasswordReset(**data)
        assert reset.email == data["email"]
    
    def test_password_reset_confirm_valid(self):
        """Test valid password reset confirmation data."""
        data = {
            "email": "test@example.com",
            "code": "123456",
            "new_password": "NewTestPass123!"
        }
        
        confirm = PasswordResetConfirm(**data)
        assert confirm.email == data["email"]
        assert confirm.code == data["code"]
        assert confirm.new_password == data["new_password"]
    
    def test_mfa_verify_valid(self):
        """Test valid MFA verification data."""
        data = {
            "session": "test-session-id",
            "code": "123456",
            "email": "test@example.com"
        }
        
        mfa = MFAVerify(**data)
        assert mfa.session == data["session"]
        assert mfa.code == data["code"]
        assert mfa.email == data["email"]