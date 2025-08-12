"""
Integration tests for CognitoService using real AWS Cognito.

WARNING: These tests will create real users in your Cognito User Pool.
Only run these tests against a development/testing User Pool.

To run these tests:
    pytest -m integration_real tests/

To exclude these tests (default):
    pytest -m "not integration_real" tests/
"""

import pytest
import asyncio
import os
from datetime import datetime
import random
import string
import boto3
from botocore.exceptions import ClientError

from custom_cognito.cognito_service import CognitoService
from custom_cognito.schemas import UserRegister
from custom_cognito.config import Settings


def generate_test_email():
    """Generate a unique test email with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    random_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"test_{timestamp}_{random_suffix}@example.com"


def generate_simple_test_email():
    """Generate a simple test email with just a random suffix."""
    random_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"test_{random_suffix}@example.com"


@pytest.fixture(scope="module")
def real_settings():
    """Load real settings from .env file."""
    # Force reload settings from .env
    settings = Settings(_env_file=".env")
    return settings


@pytest.fixture(scope="module")
def cognito_client(real_settings):
    """Create real boto3 Cognito client."""
    if real_settings.aws_profile:
        session = boto3.Session(profile_name=real_settings.aws_profile)
        return session.client("cognito-idp", region_name=real_settings.aws_region)
    elif real_settings.aws_access_key_id and real_settings.aws_secret_access_key:
        return boto3.client(
            "cognito-idp",
            region_name=real_settings.aws_region,
            aws_access_key_id=real_settings.aws_access_key_id,
            aws_secret_access_key=real_settings.aws_secret_access_key
        )
    return boto3.client("cognito-idp", region_name=real_settings.aws_region)


@pytest.fixture
def cleanup_users(cognito_client, real_settings):
    """Fixture to track and cleanup test users."""
    users_to_cleanup = []

    yield users_to_cleanup

    # Cleanup after test
    for email in users_to_cleanup:
        try:
            cognito_client.admin_delete_user(
                UserPoolId=real_settings.cognito_user_pool_id, Username=email
            )
            print(f"Cleaned up test user: {email}")
        except ClientError as e:
            if e.response["Error"]["Code"] != "UserNotFoundException":
                print(f"Error cleaning up user {email}: {e}")


@pytest.mark.integration_real
class TestRealCognitoIntegration:
    """Integration tests using real AWS Cognito."""

    @pytest.mark.timeout(30)
    def test_real_register_and_cleanup(self, real_settings, cleanup_users):
        """Test user registration with real Cognito and cleanup."""
        service = CognitoService(real_settings)
        test_email = generate_test_email()
        cleanup_users.append(test_email)

        user_data = UserRegister(
            email=test_email, password="TestPassword123!", full_name="Test User"
        )

        # Register user
        result = asyncio.run(service.register_user(user_data))

        assert result is not None
        assert result["email"] == test_email
        assert "user_sub" in result
        assert "username" in result
        assert result["confirmation_required"] is True

        print(f"Successfully registered test user: {test_email}")
        print(f"Username: {result['username']}")

    @pytest.mark.timeout(30)
    def test_real_duplicate_registration(self, real_settings, cleanup_users):
        """Test that duplicate registration fails."""
        service = CognitoService(real_settings)
        test_email = generate_test_email()
        cleanup_users.append(test_email)

        user_data = UserRegister(
            email=test_email, password="TestPassword123!", full_name="Test User"
        )

        # First registration should succeed
        result1 = asyncio.run(service.register_user(user_data))
        assert result1 is not None

        # Second registration should fail
        with pytest.raises(ValueError, match="already exists"):
            asyncio.run(service.register_user(user_data))

    @pytest.mark.timeout(30)
    def test_real_password_reset_initiation(self, real_settings, cleanup_users):
        """Test password reset initiation."""
        service = CognitoService(real_settings)
        test_email = generate_test_email()
        cleanup_users.append(test_email)

        # First register a user
        user_data = UserRegister(
            email=test_email, password="TestPassword123!", full_name="Test User"
        )
        asyncio.run(service.register_user(user_data))

        # Initiate password reset
        result = asyncio.run(service.initiate_password_reset(test_email))
        assert result is True

        print(f"Password reset initiated for: {test_email}")
        print("Note: Check email for reset code (in real scenario)")

    @pytest.mark.timeout(30)
    def test_real_login_unconfirmed_user(self, real_settings, cleanup_users):
        """Test that login fails for unconfirmed user."""
        service = CognitoService(real_settings)
        test_email = generate_test_email()
        cleanup_users.append(test_email)

        user_data = UserRegister(
            email=test_email, password="TestPassword123!", full_name="Test User"
        )

        # Register user
        asyncio.run(service.register_user(user_data))

        # Try to login without confirming email
        # Con email alias, Cognito rechaza el login completamente
        with pytest.raises(ValueError, match="Invalid email or password|Email not verified"):
            asyncio.run(service.login(test_email, "TestPassword123!"))

    @pytest.mark.timeout(30)
    def test_real_invalid_login(self, real_settings):
        """Test login with invalid credentials."""
        service = CognitoService(real_settings)

        # Try to login with non-existent user
        with pytest.raises(ValueError, match="Invalid email or password"):
            asyncio.run(service.login("nonexistent@example.com", "Password123!"))

    @pytest.mark.skip(reason="Requires manual email confirmation")
    def test_real_full_login_flow(self, real_settings, cleanup_users):
        """
        Test full login flow - REQUIRES MANUAL EMAIL CONFIRMATION.

        To run this test:
        1. Unskip this test
        2. Run the test
        3. Check the email for confirmation code
        4. Update the confirmation_code variable
        5. Run the test again
        """
        service = CognitoService(real_settings)
        test_email = "manual_test@example.com"  # Use a real email you can access
        cleanup_users.append(test_email)

        # Step 1: Register
        user_data = UserRegister(
            email=test_email, password="TestPassword123!", full_name="Test User"
        )
        result = asyncio.run(service.register_user(user_data))
        print(f"User registered: {result}")

        # Step 2: Confirm email (manual step required)
        confirmation_code = "XXXXXX"  # Replace with actual code from email
        result = asyncio.run(service.confirm_email(test_email, confirmation_code))
        assert result is True

        # Step 3: Login
        tokens = asyncio.run(service.login(test_email, "TestPassword123!"))
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert "id_token" in tokens

        print("Full login flow completed successfully!")

    @pytest.mark.timeout(30)
    def test_real_jwt_validation(self, real_settings):
        """Test JWT validation against real JWKS."""
        from custom_cognito.auth import JWTValidator

        validator = JWTValidator(real_settings)

        # Test that JWKS URL is accessible
        jwks = asyncio.run(validator._get_jwks())

        assert jwks is not None
        assert "keys" in jwks
        assert len(jwks["keys"]) > 0

        print(f"Successfully retrieved JWKS with {len(jwks['keys'])} keys")


@pytest.mark.integration_real
class TestRealCognitoServiceMethods:
    """Test individual service methods with real Cognito."""

    def test_real_secret_hash_generation(self, real_settings):
        """Test secret hash generation with real settings."""
        service = CognitoService(real_settings)

        # Test secret hash generation
        result = service._get_secret_hash("test@example.com")
        
        if real_settings.cognito_app_client_secret:
            # Si hay secret, debe generar un hash
            assert result is not None
            assert isinstance(result, str)
            assert len(result) > 0
            print(f"Secret hash generated successfully: {result[:10]}...")
        else:
            # Si no hay secret, debe ser None
            assert result is None
            print("No secret configured, hash is None as expected")

    def test_real_cognito_client_initialization(self, real_settings):
        """Test that Cognito client initializes correctly."""
        service = CognitoService(real_settings)

        # Test that we can call a simple operation
        try:
            response = service.client.describe_user_pool(
                UserPoolId=real_settings.cognito_user_pool_id
            )
            assert response is not None
            assert "UserPool" in response
            print(f"Connected to User Pool: {response['UserPool']['Name']}")
        except ClientError as e:
            pytest.fail(f"Failed to connect to Cognito: {e}")


# Helper function to run specific cleanup if needed
def cleanup_specific_user(email: str, settings: Settings):
    """Manually cleanup a specific user."""
    if settings.aws_profile:
        session = boto3.Session(profile_name=settings.aws_profile)
        client = session.client("cognito-idp", region_name=settings.aws_region)
    elif settings.aws_access_key_id and settings.aws_secret_access_key:
        client = boto3.client(
            "cognito-idp",
            region_name=settings.aws_region,
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key
        )
    else:
        client = boto3.client("cognito-idp", region_name=settings.aws_region)
    try:
        client.admin_delete_user(
            UserPoolId=settings.cognito_user_pool_id, Username=email
        )
        print(f"Deleted user: {email}")
    except ClientError as e:
        print(f"Error deleting user {email}: {e}")


if __name__ == "__main__":
    # Example of manual cleanup
    # settings = Settings(_env_file=".env")
    # cleanup_specific_user("test_email@example.com", settings)
    pass
