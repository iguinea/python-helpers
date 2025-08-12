"""
Simple tests for CognitoService that don't require AWS mocking.
"""
import pytest
from unittest.mock import Mock, patch, AsyncMock
from custom_cognito.cognito_service import CognitoService
from custom_cognito.schemas import UserRegister


class TestCognitoServiceSimple:
    """Simple tests for CognitoService without AWS dependencies."""
    
    @patch('custom_cognito.cognito_service.boto3.client')
    def test_get_secret_hash_without_secret(self, mock_boto_client):
        """Test secret hash generation when no secret is configured."""
        settings = Mock()
        settings.cognito_app_client_secret = None
        settings.aws_region = "us-east-1"
        
        service = CognitoService(settings)
        result = service._get_secret_hash("test@example.com")
        
        assert result is None
    
    @patch('custom_cognito.cognito_service.boto3.client')
    def test_get_secret_hash_with_secret(self, mock_boto_client):
        """Test secret hash generation with a secret."""
        settings = Mock()
        settings.cognito_app_client_secret = "test-secret"
        settings.cognito_app_client_id = "test-client-id"
        settings.aws_region = "us-east-1"
        
        service = CognitoService(settings)
        result = service._get_secret_hash("test@example.com")
        
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0
    
    @patch('custom_cognito.cognito_service.boto3.client')
    def test_service_initialization(self, mock_boto_client):
        """Test CognitoService initialization."""
        settings = Mock()
        settings.aws_region = "us-east-1"
        
        service = CognitoService(settings)
        
        assert service.settings == settings
        mock_boto_client.assert_called_once_with(
            'cognito-idp',
            region_name="us-east-1"
        )
    
    @patch('custom_cognito.cognito_service.boto3.client')
    @patch('custom_cognito.cognito_service.Cognito')
    def test_get_cognito_user(self, mock_cognito_class, mock_boto_client):
        """Test _get_cognito_user method."""
        settings = Mock()
        settings.cognito_user_pool_id = "test-pool"
        settings.cognito_app_client_id = "test-client"
        settings.cognito_app_client_secret = "test-secret"
        settings.aws_region = "us-east-1"
        
        service = CognitoService(settings)
        result = service._get_cognito_user("test@example.com")
        
        mock_cognito_class.assert_called_once_with(
            "test-pool",
            "test-client",
            client_secret="test-secret",
            username="test@example.com"
        )
        assert result == mock_cognito_class.return_value