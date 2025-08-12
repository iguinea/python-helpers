"""
Tests for custom_cognito imports and module structure.
"""
import pytest


class TestImports:
    """Test module imports and public API."""
    
    def test_main_module_imports(self):
        """Test that main module can be imported."""
        import custom_cognito
        
        # Check main exports
        assert hasattr(custom_cognito, "Settings")
        assert hasattr(custom_cognito, "CognitoService")
        assert hasattr(custom_cognito, "JWTValidator")
        assert hasattr(custom_cognito, "get_current_user")
        
        # Check schema exports
        assert hasattr(custom_cognito, "UserRegister")
        assert hasattr(custom_cognito, "UserLogin")
        assert hasattr(custom_cognito, "TokenResponse")
        assert hasattr(custom_cognito, "EmailVerification")
        assert hasattr(custom_cognito, "PasswordReset")
        assert hasattr(custom_cognito, "PasswordResetConfirm")
        assert hasattr(custom_cognito, "MFASetup")
        assert hasattr(custom_cognito, "MFAVerify")
        assert hasattr(custom_cognito, "RefreshToken")
    
    def test_submodule_imports(self):
        """Test that submodules can be imported."""
        from custom_cognito import config
        from custom_cognito import schemas
        from custom_cognito import cognito_service
        from custom_cognito import auth
        
        # Verify modules loaded
        assert config is not None
        assert schemas is not None
        assert cognito_service is not None
        assert auth is not None
    
    def test_version(self):
        """Test module version."""
        import custom_cognito
        assert hasattr(custom_cognito, "__version__")
        assert custom_cognito.__version__ == "0.1.0"