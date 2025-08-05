"""
Tests para el módulo de gestión de credenciales AWS.
"""

import os
from unittest.mock import Mock, patch, MagicMock
import pytest
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from custom_aws.credentials import (
    CredentialProvider,
    AWSCredentials,
    get_boto3_session,
    get_client_with_credentials,
    get_credentials_from_secret,
    assume_role_session,
    get_credentials_provider,
    validate_credentials,
)


class TestAWSCredentials:
    """Tests para la clase AWSCredentials."""
    
    def test_aws_credentials_basic(self):
        """Test creación básica de credenciales."""
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123"
        )
        assert creds.access_key_id == "AKIATEST"
        assert creds.secret_access_key == "secret123"
        assert creds.session_token is None
        assert creds.region is None
    
    def test_aws_credentials_full(self):
        """Test credenciales con todos los campos."""
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123",
            session_token="token123",
            region="us-east-1"
        )
        assert creds.session_token == "token123"
        assert creds.region == "us-east-1"
    
    def test_to_dict_basic(self):
        """Test conversión a diccionario básico."""
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123"
        )
        result = creds.to_dict()
        assert result == {
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret123"
        }
    
    def test_to_dict_full(self):
        """Test conversión a diccionario completo."""
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123",
            session_token="token123",
            region="us-east-1"
        )
        result = creds.to_dict()
        assert result == {
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret123",
            "aws_session_token": "token123",
            "region_name": "us-east-1"
        }


class TestGetBoto3Session:
    """Tests para get_boto3_session."""
    
    @patch("boto3.Session")
    def test_direct_credentials(self, mock_session):
        """Test sesión con credenciales directas."""
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123"
        )
        
        get_boto3_session(
            provider=CredentialProvider.DIRECT,
            credentials=creds
        )
        
        mock_session.assert_called_once_with(
            aws_access_key_id="AKIATEST",
            aws_secret_access_key="secret123"
        )
    
    def test_direct_credentials_missing(self):
        """Test error cuando faltan credenciales para DIRECT."""
        with pytest.raises(ValueError, match="Se requieren credenciales"):
            get_boto3_session(provider=CredentialProvider.DIRECT)
    
    @patch("custom_aws.credentials.assume_role_session")
    def test_assume_role_provider(self, mock_assume):
        """Test sesión con AssumeRole."""
        mock_session = Mock()
        mock_assume.return_value = mock_session
        
        result = get_boto3_session(
            provider=CredentialProvider.ASSUME_ROLE,
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            role_session_name="test-session",
            external_id="external123"
        )
        
        assert result == mock_session
        mock_assume.assert_called_once_with(
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            role_session_name="test-session",
            external_id="external123",
            region_name="eu-west-1"
        )
    
    @patch("custom_aws.credentials.get_credentials_from_secret")
    @patch("boto3.Session")
    def test_secrets_manager_provider(self, mock_session, mock_get_creds):
        """Test sesión con Secrets Manager."""
        mock_creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123"
        )
        mock_get_creds.return_value = mock_creds
        
        get_boto3_session(
            provider=CredentialProvider.SECRETS_MANAGER,
            secret_name="my-secret",
            region_name="us-west-2"
        )
        
        mock_get_creds.assert_called_once_with(
            secret_name="my-secret",
            region_name="us-west-2"
        )
        mock_session.assert_called_once_with(
            aws_access_key_id="AKIATEST",
            aws_secret_access_key="secret123"
        )
    
    def test_secrets_manager_missing_name(self):
        """Test error cuando falta secret_name para SECRETS_MANAGER."""
        with pytest.raises(ValueError, match="Se requiere secret_name"):
            get_boto3_session(provider=CredentialProvider.SECRETS_MANAGER)
    
    @patch("boto3.Session")
    def test_config_file_provider(self, mock_session):
        """Test sesión con archivo de configuración."""
        get_boto3_session(
            provider=CredentialProvider.CONFIG_FILE,
            profile_name="test-profile",
            region_name="us-east-1"
        )
        
        mock_session.assert_called_once_with(
            profile_name="test-profile",
            region_name="us-east-1"
        )
    
    @patch("boto3.Session")
    def test_config_file_profile_not_found(self, mock_session):
        """Test error cuando no se encuentra el perfil."""
        mock_session.side_effect = ProfileNotFound(profile="test-profile")
        
        with pytest.raises(ValueError, match="Perfil 'test-profile' no encontrado"):
            get_boto3_session(
                provider=CredentialProvider.CONFIG_FILE,
                profile_name="test-profile"
            )
    
    def test_config_file_missing_profile(self):
        """Test error cuando falta profile_name para CONFIG_FILE."""
        with pytest.raises(ValueError, match="Se requiere profile_name"):
            get_boto3_session(provider=CredentialProvider.CONFIG_FILE)
    
    @patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "AKIATEST"})
    @patch("boto3.Session")
    def test_environment_provider(self, mock_session):
        """Test sesión con variables de entorno."""
        get_boto3_session(
            provider=CredentialProvider.ENVIRONMENT,
            region_name="us-west-2"
        )
        
        mock_session.assert_called_once_with(region_name="us-west-2")
    
    @patch.dict(os.environ, {}, clear=True)
    def test_environment_no_credentials(self):
        """Test error cuando no hay credenciales en entorno."""
        with pytest.raises(NoCredentialsError):
            get_boto3_session(provider=CredentialProvider.ENVIRONMENT)
    
    @patch("boto3.Session")
    def test_instance_profile_provider(self, mock_session):
        """Test sesión con instance profile."""
        mock_client = Mock()
        mock_client.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_session.return_value.client.return_value = mock_client
        
        result = get_boto3_session(
            provider=CredentialProvider.INSTANCE_PROFILE,
            region_name="us-east-1"
        )
        
        assert result == mock_session.return_value
        mock_session.assert_called_with(region_name="us-east-1")
    
    @patch("boto3.Session")
    def test_instance_profile_no_credentials(self, mock_session):
        """Test error cuando instance profile no tiene credenciales."""
        mock_client = Mock()
        mock_client.get_caller_identity.side_effect = NoCredentialsError()
        mock_session.return_value.client.return_value = mock_client
        
        with pytest.raises(NoCredentialsError):
            get_boto3_session(provider=CredentialProvider.INSTANCE_PROFILE)
    
    def test_unsupported_provider(self):
        """Test error con proveedor no soportado."""
        with pytest.raises(ValueError, match="Proveedor de credenciales no soportado"):
            get_boto3_session(provider="invalid")
    
    @patch("boto3.Session")
    def test_auto_detect_direct(self, mock_session):
        """Test detección automática de credenciales directas."""
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123"
        )
        
        get_boto3_session(credentials=creds)
        
        mock_session.assert_called_once_with(
            aws_access_key_id="AKIATEST",
            aws_secret_access_key="secret123"
        )
    
    @patch.dict(os.environ, {"AWS_DEFAULT_REGION": "ap-southeast-1"})
    @patch("boto3.Session")
    def test_region_from_environment(self, mock_session):
        """Test obtener región de variable de entorno."""
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123"
        )
        
        get_boto3_session(credentials=creds)
        
        # La región no se pasa porque las credenciales no tienen región
        mock_session.assert_called_once_with(
            aws_access_key_id="AKIATEST",
            aws_secret_access_key="secret123"
        )


class TestGetClientWithCredentials:
    """Tests para get_client_with_credentials."""
    
    @patch("custom_aws.credentials.get_boto3_session")
    def test_get_client_basic(self, mock_get_session):
        """Test obtener cliente básico."""
        mock_session = Mock()
        mock_client = Mock()
        mock_session.client.return_value = mock_client
        mock_get_session.return_value = mock_session
        
        result = get_client_with_credentials(
            "s3",
            provider=CredentialProvider.ENVIRONMENT
        )
        
        assert result == mock_client
        mock_get_session.assert_called_once_with(provider=CredentialProvider.ENVIRONMENT)
        mock_session.client.assert_called_once_with("s3")
    
    @patch("custom_aws.credentials.get_boto3_session")
    def test_get_client_with_kwargs(self, mock_get_session):
        """Test obtener cliente con argumentos adicionales."""
        mock_session = Mock()
        mock_client = Mock()
        mock_session.client.return_value = mock_client
        mock_get_session.return_value = mock_session
        
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123"
        )
        
        result = get_client_with_credentials(
            "ec2",
            provider=CredentialProvider.DIRECT,
            credentials=creds,
            region_name="us-west-2"
        )
        
        assert result == mock_client
        mock_get_session.assert_called_once_with(
            provider=CredentialProvider.DIRECT,
            credentials=creds,
            region_name="us-west-2"
        )


class TestGetCredentialsFromSecret:
    """Tests para get_credentials_from_secret."""
    
    @patch("custom_aws.credentials.get_secret_fields")
    def test_get_credentials_basic(self, mock_get_fields):
        """Test obtener credenciales básicas de secreto."""
        mock_get_fields.return_value = {
            "access_key_id": "AKIATEST",
            "secret_access_key": "secret123"
        }
        
        result = get_credentials_from_secret("my-secret")
        
        assert isinstance(result, AWSCredentials)
        assert result.access_key_id == "AKIATEST"
        assert result.secret_access_key == "secret123"
        assert result.session_token is None
        assert result.region is None
        
        mock_get_fields.assert_called_once_with(
            secret_name="my-secret",
            fields=["access_key_id", "secret_access_key", "session_token", "region"],
            region_name=None
        )
    
    @patch("custom_aws.credentials.get_secret_fields")
    def test_get_credentials_full(self, mock_get_fields):
        """Test obtener credenciales completas de secreto."""
        mock_get_fields.return_value = {
            "access_key_id": "AKIATEST",
            "secret_access_key": "secret123",
            "session_token": "token123",
            "region": "us-east-1"
        }
        
        result = get_credentials_from_secret(
            "my-secret",
            region_name="us-west-2"
        )
        
        assert result.session_token == "token123"
        assert result.region == "us-east-1"  # Usa la región del secreto
    
    @patch("custom_aws.credentials.get_secret_fields")
    def test_get_credentials_custom_fields(self, mock_get_fields):
        """Test obtener credenciales con campos personalizados."""
        mock_get_fields.return_value = {
            "aws_access_key": "AKIATEST",
            "aws_secret_key": "secret123",
            "aws_session": "token123",
            "aws_region": "eu-west-1"
        }
        
        result = get_credentials_from_secret(
            "my-secret",
            access_key_field="aws_access_key",
            secret_key_field="aws_secret_key",
            session_token_field="aws_session",
            region_field="aws_region"
        )
        
        assert result.access_key_id == "AKIATEST"
        assert result.secret_access_key == "secret123"
        assert result.session_token == "token123"
        assert result.region == "eu-west-1"
        
        mock_get_fields.assert_called_once_with(
            secret_name="my-secret",
            fields=["aws_access_key", "aws_secret_key", "aws_session", "aws_region"],
            region_name=None
        )
    
    @patch("custom_aws.credentials.get_secret_fields")
    def test_get_credentials_missing_access_key(self, mock_get_fields):
        """Test error cuando falta access key."""
        mock_get_fields.return_value = {
            "secret_access_key": "secret123"
        }
        
        with pytest.raises(ValueError, match="Campo requerido 'access_key_id' no encontrado"):
            get_credentials_from_secret("my-secret")
    
    @patch("custom_aws.credentials.get_secret_fields")
    def test_get_credentials_missing_secret_key(self, mock_get_fields):
        """Test error cuando falta secret key."""
        mock_get_fields.return_value = {
            "access_key_id": "AKIATEST"
        }
        
        with pytest.raises(ValueError, match="Campo requerido 'secret_access_key' no encontrado"):
            get_credentials_from_secret("my-secret")
    
    @patch("custom_aws.credentials.get_secret_fields")
    def test_get_credentials_aws_error(self, mock_get_fields):
        """Test manejo de errores de AWS."""
        mock_get_fields.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException"}},
            "GetSecretValue"
        )
        
        with pytest.raises(ValueError, match="Error al obtener credenciales del secreto"):
            get_credentials_from_secret("my-secret")


class TestAssumeRoleSession:
    """Tests para assume_role_session."""
    
    @patch("boto3.client")
    @patch("boto3.Session")
    def test_assume_role_basic(self, mock_session, mock_client):
        """Test asumir rol básico."""
        mock_sts = Mock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "secret123",
                "SessionToken": "token123"
            }
        }
        mock_client.return_value = mock_sts
        
        result = assume_role_session(
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            role_session_name="test-session"
        )
        
        mock_client.assert_called_once_with("sts", region_name=None)
        mock_sts.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::123456789012:role/TestRole",
            RoleSessionName="test-session",
            DurationSeconds=3600
        )
        mock_session.assert_called_once_with(
            aws_access_key_id="AKIATEST",
            aws_secret_access_key="secret123",
            aws_session_token="token123",
            region_name=None
        )
    
    @patch("boto3.client")
    def test_assume_role_with_external_id(self, mock_client):
        """Test asumir rol con external ID."""
        mock_sts = Mock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "secret123",
                "SessionToken": "token123"
            }
        }
        mock_client.return_value = mock_sts
        
        assume_role_session(
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            role_session_name="test-session",
            external_id="external123",
            duration_seconds=7200,
            region_name="us-west-2"
        )
        
        mock_sts.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::123456789012:role/TestRole",
            RoleSessionName="test-session",
            DurationSeconds=7200,
            ExternalId="external123"
        )
    
    def test_assume_role_no_arn(self):
        """Test error cuando falta role_arn."""
        with pytest.raises(ValueError, match="Se requiere role_arn"):
            assume_role_session(
                role_arn="",
                role_session_name="test-session"
            )
    
    @patch("boto3.client")
    def test_assume_role_access_denied(self, mock_client):
        """Test error de acceso denegado."""
        mock_sts = Mock()
        mock_sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "AssumeRole"
        )
        mock_client.return_value = mock_sts
        
        with pytest.raises(PermissionError, match="Acceso denegado"):
            assume_role_session(
                role_arn="arn:aws:iam::123456789012:role/TestRole",
                role_session_name="test-session"
            )
    
    @patch("boto3.Session")
    def test_assume_role_with_base_session(self, mock_session_class):
        """Test asumir rol con sesión base."""
        base_session = Mock()
        mock_sts = Mock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AKIATEST",
                "SecretAccessKey": "secret123",
                "SessionToken": "token123"
            }
        }
        base_session.client.return_value = mock_sts
        
        assume_role_session(
            role_arn="arn:aws:iam::123456789012:role/TestRole",
            role_session_name="test-session",
            base_session=base_session
        )
        
        base_session.client.assert_called_once_with("sts")


class TestGetCredentialsProvider:
    """Tests para get_credentials_provider."""
    
    def test_detect_direct(self):
        """Test detectar credenciales directas."""
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123"
        )
        result = get_credentials_provider(credentials=creds)
        assert result == CredentialProvider.DIRECT
    
    def test_detect_secrets_manager(self):
        """Test detectar Secrets Manager."""
        result = get_credentials_provider(secret_name="my-secret")
        assert result == CredentialProvider.SECRETS_MANAGER
    
    def test_detect_assume_role(self):
        """Test detectar AssumeRole."""
        result = get_credentials_provider(
            role_arn="arn:aws:iam::123456789012:role/TestRole"
        )
        assert result == CredentialProvider.ASSUME_ROLE
    
    def test_detect_config_file(self):
        """Test detectar archivo de configuración."""
        result = get_credentials_provider(profile_name="test-profile")
        assert result == CredentialProvider.CONFIG_FILE
    
    @patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "AKIATEST"})
    def test_detect_environment(self):
        """Test detectar variables de entorno."""
        result = get_credentials_provider()
        assert result == CredentialProvider.ENVIRONMENT
    
    @patch.dict(os.environ, {}, clear=True)
    def test_detect_instance_profile(self):
        """Test detectar instance profile por defecto."""
        result = get_credentials_provider()
        assert result == CredentialProvider.INSTANCE_PROFILE
    
    @patch.dict(os.environ, {"AWS_EXECUTION_ENV": "AWS_ECS_EC2"})
    def test_detect_ecs_environment(self):
        """Test detectar ambiente ECS."""
        result = get_credentials_provider()
        assert result == CredentialProvider.INSTANCE_PROFILE
    
    def test_detect_priority_order(self):
        """Test orden de prioridad en detección."""
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123"
        )
        
        # Credenciales directas tienen prioridad
        result = get_credentials_provider(
            credentials=creds,
            secret_name="my-secret",
            role_arn="arn:aws:iam::123456789012:role/TestRole"
        )
        assert result == CredentialProvider.DIRECT


class TestValidateCredentials:
    """Tests para validate_credentials."""
    
    def test_validate_with_session(self):
        """Test validar con sesión existente."""
        mock_session = Mock()
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_session.client.return_value = mock_sts
        
        result = validate_credentials(session=mock_session)
        
        assert result is True
        mock_session.client.assert_called_once_with("sts")
        mock_sts.get_caller_identity.assert_called_once()
    
    @patch("boto3.Session")
    def test_validate_with_credentials(self, mock_session_class):
        """Test validar con credenciales."""
        creds = AWSCredentials(
            access_key_id="AKIATEST",
            secret_access_key="secret123"
        )
        
        mock_session = Mock()
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_session.client.return_value = mock_sts
        mock_session_class.return_value = mock_session
        
        result = validate_credentials(credentials=creds)
        
        assert result is True
        mock_session_class.assert_called_once_with(
            aws_access_key_id="AKIATEST",
            aws_secret_access_key="secret123"
        )
    
    @patch("custom_aws.credentials.get_boto3_session")
    def test_validate_with_provider(self, mock_get_session):
        """Test validar con proveedor."""
        mock_session = Mock()
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_session.client.return_value = mock_sts
        mock_get_session.return_value = mock_session
        
        result = validate_credentials(
            provider=CredentialProvider.ENVIRONMENT,
            region_name="us-west-2"
        )
        
        assert result is True
        mock_get_session.assert_called_once_with(
            provider=CredentialProvider.ENVIRONMENT,
            credentials=None,
            region_name="us-west-2"
        )
    
    def test_validate_no_credentials(self):
        """Test validar sin credenciales."""
        mock_session = Mock()
        mock_sts = Mock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        mock_session.client.return_value = mock_sts
        
        result = validate_credentials(session=mock_session)
        
        assert result is False
    
    def test_validate_invalid_credentials(self):
        """Test validar credenciales inválidas."""
        mock_session = Mock()
        mock_sts = Mock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "InvalidUserID.NotFound"}},
            "GetCallerIdentity"
        )
        mock_session.client.return_value = mock_sts
        
        result = validate_credentials(session=mock_session)
        
        assert result is False
    
    def test_validate_no_account(self):
        """Test validar cuando no hay cuenta en respuesta."""
        mock_session = Mock()
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {}
        mock_session.client.return_value = mock_sts
        
        result = validate_credentials(session=mock_session)
        
        assert result is False
    
    def test_validate_unexpected_error(self):
        """Test validar con error inesperado."""
        mock_session = Mock()
        mock_sts = Mock()
        mock_sts.get_caller_identity.side_effect = Exception("Unexpected error")
        mock_session.client.return_value = mock_sts
        
        result = validate_credentials(session=mock_session)
        
        assert result is False