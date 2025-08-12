"""
Tests for CognitoService class.
"""
import pytest
import asyncio
from moto import mock_aws
from botocore.exceptions import ClientError

from custom_cognito.cognito_service import CognitoService
from custom_cognito.schemas import UserRegister

@mock_aws
class TestCognitoService:
    """Test cases for CognitoService."""
    
    def test_register_user_success(self, test_settings, user_pool, test_user_data):
        """Test successful user registration."""
        service = CognitoService(test_settings)
        
        user_data = UserRegister(**test_user_data)
        result = asyncio.run(service.register_user(user_data))
        
        assert result["email"] == test_user_data["email"]
        assert "user_sub" in result
        assert result["confirmation_required"] is True
    
    def test_register_duplicate_user(self, test_settings, user_pool, test_user_data):
        """Test registering duplicate user."""
        service = CognitoService(test_settings)
        
        # Register first user
        user_data = UserRegister(**test_user_data)
        asyncio.run(service.register_user(user_data))
        
        # Try to register same user again
        with pytest.raises(ValueError, match="already exists"):
            asyncio.run(service.register_user(user_data))
    
    def test_confirm_email_success(self, test_settings, user_pool, test_user_data):
        """Test successful email confirmation."""
        service = CognitoService(test_settings)
        
        # Register user
        user_data = UserRegister(**test_user_data)
        asyncio.run(service.register_user(user_data))
        
        # In real scenario, we'd get the code from email
        # For testing, we'll use admin confirm
        user_pool["client"].admin_confirm_sign_up(
            UserPoolId=user_pool["pool_id"],
            Username=test_user_data["email"]
        )
        
        # Verify user is confirmed
        user = user_pool["client"].admin_get_user(
            UserPoolId=user_pool["pool_id"],
            Username=test_user_data["email"]
        )
        assert user["UserStatus"] == "CONFIRMED"
    
    def test_login_success(self, test_settings, user_pool, test_user_data):
        """Test successful login."""
        service = CognitoService(test_settings)
        
        # Register and confirm user
        user_data = UserRegister(**test_user_data)
        asyncio.run(service.register_user(user_data))
        
        user_pool["client"].admin_confirm_sign_up(
            UserPoolId=user_pool["pool_id"],
            Username=test_user_data["email"]
        )
        
        # Set permanent password
        user_pool["client"].admin_set_user_password(
            UserPoolId=user_pool["pool_id"],
            Username=test_user_data["email"],
            Password=test_user_data["password"],
            Permanent=True
        )
        
        # Test login
        result = asyncio.run(
            service.login(test_user_data["email"], test_user_data["password"])
        )
        
        assert "access_token" in result
        assert "refresh_token" in result
        assert "id_token" in result
        assert result["expires_in"] > 0
    
    def test_login_invalid_credentials(self, test_settings, user_pool, test_user_data):
        """Test login with invalid credentials."""
        service = CognitoService(test_settings)
        
        # Register and confirm user
        user_data = UserRegister(**test_user_data)
        asyncio.run(service.register_user(user_data))
        
        user_pool["client"].admin_confirm_sign_up(
            UserPoolId=user_pool["pool_id"],
            Username=test_user_data["email"]
        )
        
        # Try login with wrong password
        with pytest.raises(ValueError, match="Invalid email or password"):
            asyncio.run(
                service.login(test_user_data["email"], "WrongPassword123!")
            )
    
    def test_initiate_password_reset(self, test_settings, user_pool, test_user_data):
        """Test password reset initiation."""
        service = CognitoService(test_settings)
        
        # Register and confirm user
        user_data = UserRegister(**test_user_data)
        asyncio.run(service.register_user(user_data))
        
        user_pool["client"].admin_confirm_sign_up(
            UserPoolId=user_pool["pool_id"],
            Username=test_user_data["email"]
        )
        
        # Initiate password reset
        result = asyncio.run(
            service.initiate_password_reset(test_user_data["email"])
        )
        
        assert result is True
    
    def test_logout_success(self, test_settings, user_pool, test_user_data):
        """Test successful logout."""
        service = CognitoService(test_settings)
        
        # Register, confirm and login user
        user_data = UserRegister(**test_user_data)
        asyncio.run(service.register_user(user_data))
        
        user_pool["client"].admin_confirm_sign_up(
            UserPoolId=user_pool["pool_id"],
            Username=test_user_data["email"]
        )
        
        user_pool["client"].admin_set_user_password(
            UserPoolId=user_pool["pool_id"],
            Username=test_user_data["email"],
            Password=test_user_data["password"],
            Permanent=True
        )
        
        login_result = asyncio.run(
            service.login(test_user_data["email"], test_user_data["password"])
        )
        
        # Test logout
        result = asyncio.run(
            service.logout(login_result["access_token"])
        )
        
        assert result is True