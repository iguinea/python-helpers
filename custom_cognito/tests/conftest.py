"""
Pytest configuration and fixtures for custom_cognito tests.
"""
import os
import pytest
from moto import mock_aws
import boto3
from fastapi.testclient import TestClient
from dotenv import load_dotenv

# Load test environment variables
load_dotenv(".env.test")

@pytest.fixture(scope="session")
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_REGION"] = "us-east-1"

@pytest.fixture(scope="function")
def cognito_client(aws_credentials):
    """Create a mocked Cognito client."""
    with mock_aws():
        yield boto3.client("cognito-idp", region_name="us-east-1")

@pytest.fixture(scope="function")
def user_pool(cognito_client):
    """Create a test user pool."""
    response = cognito_client.create_user_pool(
        PoolName="test-pool",
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        AutoVerifiedAttributes=["email"],
        UsernameAttributes=["email"],
        Schema=[
            {
                "Name": "email",
                "AttributeDataType": "String",
                "Required": True,
                "Mutable": True,
            },
            {
                "Name": "name",
                "AttributeDataType": "String",
                "Required": False,
                "Mutable": True,
            },
            {
                "Name": "phone_number",
                "AttributeDataType": "String",
                "Required": False,
                "Mutable": True,
            },
        ],
    )
    
    pool_id = response["UserPool"]["Id"]
    
    # Create app client
    app_client = cognito_client.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="test-client",
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )
    
    return {
        "pool_id": pool_id,
        "client_id": app_client["UserPoolClient"]["ClientId"],
        "client": cognito_client,
    }

@pytest.fixture(scope="function")
def test_settings(user_pool):
    """Create test settings."""
    from custom_cognito.config import Settings
    
    return Settings(
        aws_region="us-east-1",
        cognito_user_pool_id=user_pool["pool_id"],
        cognito_app_client_id=user_pool["client_id"],
        cognito_app_client_secret=None,
        frontend_url="http://localhost:3000",
        redis_url="redis://localhost:6379/0",
        jwt_secret_key="test-secret-key",
        environment="test",
        access_token_expire_minutes=60,
        refresh_token_expire_days=30,
    )

@pytest.fixture(scope="function")
def test_app(test_settings, monkeypatch):
    """Create test FastAPI application."""
    # Monkey patch the settings
    monkeypatch.setattr("custom_cognito.config.settings", test_settings)
    monkeypatch.setattr("custom_cognito.config._settings", test_settings)
    monkeypatch.setattr("custom_cognito.config.get_settings", lambda: test_settings)
    
    # Reset the JWT validator and cognito service singletons
    monkeypatch.setattr("custom_cognito.auth._jwt_validator", None)
    monkeypatch.setattr("custom_cognito.main._cognito_service", None)
    
    from custom_cognito.main import app
    
    return TestClient(app)

@pytest.fixture
def test_user_data():
    """Sample user registration data."""
    return {
        "email": "test@example.com",
        "password": "TestPass123!",
        "full_name": "Test User",
        "phone_number": "+1234567890",
    }