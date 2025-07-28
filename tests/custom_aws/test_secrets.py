"""
Tests para el módulo custom_aws.secrets
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError, NoCredentialsError

from custom_aws.secrets import (
    _get_secret_value,
    parse_secret_json,
    get_secret_fields,
    check_secrets_manager_connection
)


class TestGetSecretValue:
    """Tests para _get_secret_value"""
    
    @pytest.mark.unit
    def test_get_secret_string_success(self, mock_secrets_manager):
        """Test obtención exitosa de un secreto string."""
        secret_name = "test-secret"
        secret_value = "my-secret-value"
        
        # Crear secreto
        mock_secrets_manager.create_secret(
            Name=secret_name,
            SecretString=secret_value
        )
        
        # Obtener secreto
        result = _get_secret_value(secret_name)
        assert result == secret_value
    
    @pytest.mark.unit
    def test_get_secret_binary_success(self, mock_secrets_manager):
        """Test obtención exitosa de un secreto binario."""
        secret_name = "test-binary-secret"
        secret_value = b"binary-secret-data"
        
        # Crear secreto binario
        mock_secrets_manager.create_secret(
            Name=secret_name,
            SecretBinary=secret_value
        )
        
        # Obtener secreto
        result = _get_secret_value(secret_name)
        assert result == secret_value
    
    @pytest.mark.unit
    def test_get_secret_not_found(self, mock_secrets_manager):
        """Test error cuando el secreto no existe."""
        with pytest.raises(ValueError, match="Secret non-existent not found"):
            _get_secret_value("non-existent")
    
    @pytest.mark.unit
    def test_get_secret_access_denied(self, mock_secrets_manager):
        """Test error de permisos."""
        with patch('boto3.Session') as mock_session:
            mock_client = MagicMock()
            mock_session.return_value.client.return_value = mock_client
            
            # Simular error de permisos
            mock_client.get_secret_value.side_effect = ClientError(
                {'Error': {'Code': 'AccessDeniedException'}},
                'GetSecretValue'
            )
            
            with pytest.raises(PermissionError, match="Access denied"):
                _get_secret_value("secret")
    
    @pytest.mark.unit
    def test_get_secret_no_credentials(self):
        """Test error cuando no hay credenciales AWS."""
        with patch('boto3.Session') as mock_session:
            mock_session.side_effect = NoCredentialsError()
            
            with pytest.raises(NoCredentialsError):
                _get_secret_value("secret")
    
    @pytest.mark.unit
    def test_get_secret_with_custom_region(self, mock_aws_credentials):
        """Test con región personalizada."""
        with patch('boto3.Session') as mock_session:
            mock_client = MagicMock()
            mock_session.return_value.client.return_value = mock_client
            
            mock_client.get_secret_value.return_value = {
                'SecretString': 'test-value'
            }
            
            result = _get_secret_value("secret", region_name="eu-west-1")
            
            # Verificar que se usó la región correcta
            mock_session.return_value.client.assert_called_with(
                service_name="secretsmanager",
                region_name="eu-west-1"
            )
            assert result == "test-value"


class TestParseSecretJson:
    """Tests para parse_secret_json"""
    
    @pytest.mark.unit
    def test_parse_valid_json(self):
        """Test parseo de JSON válido."""
        secret_json = '{"key": "value", "number": 42}'
        result = parse_secret_json(secret_json)
        
        assert result == {"key": "value", "number": 42}
    
    @pytest.mark.unit
    def test_parse_invalid_json(self):
        """Test error con JSON inválido."""
        with pytest.raises(ValueError, match="not valid JSON"):
            parse_secret_json("not-json{")
    
    @pytest.mark.unit
    def test_parse_non_object_json(self):
        """Test error cuando JSON no es un objeto."""
        with pytest.raises(ValueError, match="must be a JSON object"):
            parse_secret_json('"just a string"')
    
    @pytest.mark.unit
    def test_parse_with_required_fields_success(self):
        """Test validación exitosa de campos requeridos."""
        secret_json = '{"field1": "value1", "field2": "value2"}'
        result = parse_secret_json(secret_json, required_fields=["field1", "field2"])
        
        assert result["field1"] == "value1"
        assert result["field2"] == "value2"
    
    @pytest.mark.unit
    def test_parse_missing_required_fields(self):
        """Test error cuando faltan campos requeridos."""
        secret_json = '{"field1": "value1"}'
        
        with pytest.raises(ValueError, match="missing required fields: field2, field3"):
            parse_secret_json(secret_json, required_fields=["field1", "field2", "field3"])


class TestGetSecretFields:
    """Tests para get_secret_fields"""
    
    @pytest.mark.unit
    def test_get_fields_success(self, mock_secrets_manager):
        """Test obtención exitosa de campos específicos."""
        secret_name = "test-config"
        secret_data = {
            "api_key": "abc123",
            "endpoint": "https://api.example.com",
            "timeout": 30
        }
        
        # Crear secreto
        mock_secrets_manager.create_secret(
            Name=secret_name,
            SecretString=json.dumps(secret_data)
        )
        
        # Obtener campos específicos
        result = get_secret_fields(
            secret_name,
            ["api_key", "endpoint"]
        )
        
        assert result == {
            "api_key": "abc123",
            "endpoint": "https://api.example.com"
        }
        assert "timeout" not in result
    
    @pytest.mark.unit
    def test_get_fields_empty_list(self, mock_secrets_manager):
        """Test error con lista de campos vacía."""
        with pytest.raises(ValueError, match="Fields list cannot be empty"):
            get_secret_fields("secret", [])
    
    @pytest.mark.unit
    def test_get_fields_binary_secret(self, mock_secrets_manager):
        """Test error con secreto binario."""
        secret_name = "binary-secret"
        
        # Crear secreto binario
        mock_secrets_manager.create_secret(
            Name=secret_name,
            SecretBinary=b"binary-data"
        )
        
        with pytest.raises(ValueError, match="stored as binary, expected JSON"):
            get_secret_fields(secret_name, ["field"])
    
    @pytest.mark.unit
    def test_get_fields_missing_required(self, mock_secrets_manager):
        """Test error cuando faltan campos requeridos."""
        secret_name = "incomplete-secret"
        secret_data = {"field1": "value1"}
        
        mock_secrets_manager.create_secret(
            Name=secret_name,
            SecretString=json.dumps(secret_data)
        )
        
        with pytest.raises(ValueError, match="Secret missing required fields: field2"):
            get_secret_fields(secret_name, ["field1", "field2"], allow_missing=False)
    
    @pytest.mark.unit
    def test_get_fields_allow_missing(self, mock_secrets_manager):
        """Test permitir campos faltantes."""
        secret_name = "partial-secret"
        secret_data = {"field1": "value1"}
        
        mock_secrets_manager.create_secret(
            Name=secret_name,
            SecretString=json.dumps(secret_data)
        )
        
        result = get_secret_fields(
            secret_name,
            ["field1", "field2", "field3"],
            allow_missing=True
        )
        
        assert result == {"field1": "value1"}
    
    @pytest.mark.unit
    def test_get_fields_none_found(self, mock_secrets_manager):
        """Test error cuando no se encuentra ningún campo solicitado."""
        secret_name = "wrong-secret"
        secret_data = {"other_field": "value"}
        
        mock_secrets_manager.create_secret(
            Name=secret_name,
            SecretString=json.dumps(secret_data)
        )
        
        with pytest.raises(ValueError, match="contains none of the requested fields"):
            get_secret_fields(
                secret_name,
                ["field1", "field2"],
                allow_missing=True
            )
    
    @pytest.mark.integration
    def test_get_fields_with_region(self, mock_secrets_manager):
        """Test con región específica."""
        # Crear cliente en otra región
        import boto3
        from moto import mock_aws
        
        with mock_aws():
            client_eu = boto3.client("secretsmanager", region_name="eu-west-1")
            
            secret_name = "regional-secret"
            secret_data = {"key": "value"}
            
            client_eu.create_secret(
                Name=secret_name,
                SecretString=json.dumps(secret_data)
            )
            
            result = get_secret_fields(
                secret_name,
                ["key"],
                region_name="eu-west-1"
            )
            
            assert result == {"key": "value"}


class TestSecretsManagerConnection:
    """Tests para check_secrets_manager_connection"""
    
    @pytest.mark.unit
    def test_connection_success(self, mock_secrets_manager):
        """Test conexión exitosa."""
        result = check_secrets_manager_connection()
        assert result is True
    
    @pytest.mark.unit
    def test_connection_failure(self):
        """Test fallo de conexión."""
        with patch('boto3.Session') as mock_session:
            mock_session.side_effect = Exception("Connection error")
            
            result = check_secrets_manager_connection()
            assert result is False
    
    @pytest.mark.unit
    def test_connection_with_region(self, mock_aws_credentials):
        """Test conexión con región específica."""
        with patch('boto3.Session') as mock_session:
            mock_client = MagicMock()
            mock_session.return_value.client.return_value = mock_client
            
            result = check_secrets_manager_connection(region_name="ap-southeast-1")
            
            # Verificar que se usó la región correcta
            mock_session.return_value.client.assert_called_with(
                service_name="secretsmanager",
                region_name="ap-southeast-1"
            )
            assert result is True