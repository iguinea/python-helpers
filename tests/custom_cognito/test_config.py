"""
Tests for custom_cognito configuration.
"""
import os
import pytest
from custom_cognito.config import Settings


class TestConfig:
    """Test configuration handling."""
    
    def test_settings_with_env_vars(self, monkeypatch):
        """Test Settings instantiation with environment variables."""
        # Set required environment variables
        monkeypatch.setenv("COGNITO_USER_POOL_ID", "test-pool-id")
        monkeypatch.setenv("COGNITO_APP_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")
        
        # Create settings
        settings = Settings()
        
        # Verify settings
        assert settings.cognito_user_pool_id == "test-pool-id"
        assert settings.cognito_app_client_id == "test-client-id"
        assert settings.jwt_secret_key == "test-secret-key"
        assert settings.aws_region == "eu-west-1"  # default
        assert settings.environment == "development"  # default
        
    def test_settings_defaults(self, monkeypatch):
        """Test Settings default values."""
        # Set only required fields
        monkeypatch.setenv("COGNITO_USER_POOL_ID", "test-pool-id")
        monkeypatch.setenv("COGNITO_APP_CLIENT_ID", "test-client-id")
        monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")
        
        settings = Settings()
        
        # Check defaults
        assert settings.frontend_url == "http://localhost:3000"
        assert settings.redis_url == "redis://localhost:6379/0"
        assert settings.access_token_expire_minutes == 60
        assert settings.refresh_token_expire_days == 30
        assert settings.cognito_app_client_secret is None
        
    def test_settings_missing_required_fields(self):
        """Test Settings validation with missing required fields."""
        with pytest.raises(ValueError):
            Settings()