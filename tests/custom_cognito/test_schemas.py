"""
Tests for custom_cognito schemas.
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


class TestUserRegisterSchema:
    """Test UserRegister schema validation."""
    
    def test_valid_user_register(self):
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
    
    def test_user_register_without_phone(self):
        """Test user registration without optional phone number."""
        data = {
            "email": "test@example.com",
            "password": "TestPass123!",
            "full_name": "Test User"
        }
        
        user = UserRegister(**data)
        assert user.phone_number is None
    
    def test_invalid_email(self):
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
    
    def test_weak_password(self):
        """Test password validation rules."""
        base_data = {
            "email": "test@example.com",
            "full_name": "Test User"
        }
        
        # Missing digit
        with pytest.raises(ValidationError, match="at least one digit"):
            UserRegister(**{**base_data, "password": "TestPass!"})
        
        # Missing uppercase
        with pytest.raises(ValidationError, match="at least one uppercase"):
            UserRegister(**{**base_data, "password": "testpass123!"})
        
        # Missing lowercase
        with pytest.raises(ValidationError, match="at least one lowercase"):
            UserRegister(**{**base_data, "password": "TESTPASS123!"})
        
        # Missing special character
        with pytest.raises(ValidationError, match="at least one special character"):
            UserRegister(**{**base_data, "password": "TestPass123"})
        
        # Too short
        with pytest.raises(ValidationError):
            UserRegister(**{**base_data, "password": "Tp1!"})


class TestOtherSchemas:
    """Test other schema validations."""
    
    def test_user_login(self):
        """Test UserLogin schema."""
        data = {"email": "test@example.com", "password": "password"}
        login = UserLogin(**data)
        assert login.email == data["email"]
        assert login.password == data["password"]
    
    def test_email_verification(self):
        """Test EmailVerification schema."""
        data = {"email": "test@example.com", "code": "123456"}
        verification = EmailVerification(**data)
        assert verification.email == data["email"]
        assert verification.code == data["code"]
    
    def test_password_reset(self):
        """Test PasswordReset schema."""
        data = {"email": "test@example.com"}
        reset = PasswordReset(**data)
        assert reset.email == data["email"]
    
    def test_password_reset_confirm(self):
        """Test PasswordResetConfirm schema."""
        data = {
            "email": "test@example.com",
            "code": "123456",
            "new_password": "NewTestPass123!"
        }
        confirm = PasswordResetConfirm(**data)
        assert confirm.email == data["email"]
        assert confirm.code == data["code"]
        assert confirm.new_password == data["new_password"]
    
    def test_mfa_verify(self):
        """Test MFAVerify schema."""
        data = {
            "session": "test-session",
            "code": "123456",
            "email": "test@example.com"
        }
        mfa = MFAVerify(**data)
        assert mfa.session == data["session"]
        assert mfa.code == data["code"]
        assert mfa.email == data["email"]