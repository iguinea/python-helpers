"""
Utilidades para gestión de credenciales AWS en aplicaciones Python.

Proporciona múltiples métodos para obtener y gestionar credenciales AWS:
- Credenciales directas
- AssumeRole con STS
- Instance profiles
- AWS Secrets Manager
- Variables de entorno
- Archivos de configuración
"""

import os
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass
from enum import Enum
import boto3
from botocore.client import BaseClient
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from botocore.session import Session

from .secrets import get_secret_fields


class CredentialProvider(Enum):
    """Tipos de proveedores de credenciales soportados."""
    DIRECT = "direct"
    ASSUME_ROLE = "assume_role"
    SECRETS_MANAGER = "secrets_manager"
    ENVIRONMENT = "environment"
    INSTANCE_PROFILE = "instance_profile"
    CONFIG_FILE = "config_file"


@dataclass
class AWSCredentials:
    """Contenedor para credenciales AWS."""
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    region: Optional[str] = None
    
    def to_dict(self) -> Dict[str, str]:
        """Convertir a diccionario para usar con boto3."""
        creds = {
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
        }
        if self.session_token:
            creds["aws_session_token"] = self.session_token
        if self.region:
            creds["region_name"] = self.region
        return creds


def get_boto3_session(
    provider: Optional[CredentialProvider] = None,
    region_name: Optional[str] = None,
    profile_name: Optional[str] = None,
    credentials: Optional[AWSCredentials] = None,
    role_arn: Optional[str] = None,
    role_session_name: Optional[str] = None,
    external_id: Optional[str] = None,
    secret_name: Optional[str] = None,
    secret_region: Optional[str] = None,
) -> boto3.Session:
    """
    Crear una sesión de boto3 con el proveedor de credenciales especificado.
    
    Args:
        provider: Tipo de proveedor de credenciales a usar
        region_name: Región AWS a usar
        profile_name: Nombre del perfil AWS (para CONFIG_FILE)
        credentials: Credenciales directas (para DIRECT)
        role_arn: ARN del rol a asumir (para ASSUME_ROLE)
        role_session_name: Nombre de sesión para AssumeRole
        external_id: ID externo para AssumeRole
        secret_name: Nombre del secreto en Secrets Manager
        secret_region: Región del secreto (si es diferente)
        
    Returns:
        boto3.Session: Sesión configurada con las credenciales
        
    Raises:
        ValueError: Si faltan parámetros requeridos para el proveedor
        NoCredentialsError: Si no se pueden obtener credenciales
        ClientError: Para errores de AWS
    """
    # Usar región por defecto si no se especifica
    if not region_name:
        region_name = os.environ.get("AWS_DEFAULT_REGION", "eu-west-1")
    
    # Detectar proveedor automáticamente si no se especifica
    if not provider:
        provider = _detect_credential_provider(
            credentials=credentials,
            role_arn=role_arn,
            secret_name=secret_name,
            profile_name=profile_name
        )
    
    if provider == CredentialProvider.DIRECT:
        if not credentials:
            raise ValueError("Se requieren credenciales para el proveedor DIRECT")
        return boto3.Session(**credentials.to_dict())
    
    elif provider == CredentialProvider.ASSUME_ROLE:
        return assume_role_session(
            role_arn=role_arn,
            role_session_name=role_session_name or "python-helpers-session",
            external_id=external_id,
            region_name=region_name
        )
    
    elif provider == CredentialProvider.SECRETS_MANAGER:
        if not secret_name:
            raise ValueError("Se requiere secret_name para el proveedor SECRETS_MANAGER")
        creds = get_credentials_from_secret(
            secret_name=secret_name,
            region_name=secret_region or region_name
        )
        return boto3.Session(**creds.to_dict())
    
    elif provider == CredentialProvider.CONFIG_FILE:
        if not profile_name:
            raise ValueError("Se requiere profile_name para el proveedor CONFIG_FILE")
        try:
            return boto3.Session(profile_name=profile_name, region_name=region_name)
        except ProfileNotFound as e:
            raise ValueError(f"Perfil '{profile_name}' no encontrado en configuración AWS") from e
    
    elif provider == CredentialProvider.ENVIRONMENT:
        # Verificar que existan las variables de entorno necesarias
        if not os.environ.get("AWS_ACCESS_KEY_ID"):
            raise NoCredentialsError()
        return boto3.Session(region_name=region_name)
    
    elif provider == CredentialProvider.INSTANCE_PROFILE:
        # boto3 intentará usar el instance profile automáticamente
        session = boto3.Session(region_name=region_name)
        # Verificar que funcione
        try:
            sts = session.client("sts")
            sts.get_caller_identity()
        except NoCredentialsError:
            raise
        return session
    
    else:
        raise ValueError(f"Proveedor de credenciales no soportado: {provider}")


def get_client_with_credentials(
    service_name: str,
    provider: Optional[CredentialProvider] = None,
    **kwargs
) -> BaseClient:
    """
    Obtener un cliente boto3 con credenciales específicas.
    
    Args:
        service_name: Nombre del servicio AWS (ej: 's3', 'ec2', 'sts')
        provider: Tipo de proveedor de credenciales
        **kwargs: Argumentos adicionales para get_boto3_session
        
    Returns:
        BaseClient: Cliente boto3 configurado
    """
    session = get_boto3_session(provider=provider, **kwargs)
    return session.client(service_name)


def get_credentials_from_secret(
    secret_name: str,
    region_name: Optional[str] = None,
    access_key_field: str = "access_key_id",
    secret_key_field: str = "secret_access_key",
    session_token_field: str = "session_token",
    region_field: str = "region",
) -> AWSCredentials:
    """
    Obtener credenciales AWS desde AWS Secrets Manager.
    
    Args:
        secret_name: Nombre o ARN del secreto
        region_name: Región donde está el secreto
        access_key_field: Nombre del campo para access key
        secret_key_field: Nombre del campo para secret key
        session_token_field: Nombre del campo para session token
        region_field: Nombre del campo para región
        
    Returns:
        AWSCredentials: Credenciales obtenidas del secreto
        
    Raises:
        ValueError: Si faltan campos requeridos en el secreto
        ClientError: Para errores de AWS
    """
    # Obtener todos los campos posibles
    fields = [access_key_field, secret_key_field, session_token_field, region_field]
    
    try:
        secret_data = get_secret_fields(
            secret_name=secret_name,
            fields=fields,
            region_name=region_name
        )
    except Exception as e:
        # Re-lanzar con mensaje más específico
        raise ValueError(f"Error al obtener credenciales del secreto '{secret_name}': {e}") from e
    
    # Verificar campos requeridos
    if access_key_field not in secret_data:
        raise ValueError(f"Campo requerido '{access_key_field}' no encontrado en el secreto")
    if secret_key_field not in secret_data:
        raise ValueError(f"Campo requerido '{secret_key_field}' no encontrado en el secreto")
    
    return AWSCredentials(
        access_key_id=secret_data[access_key_field],
        secret_access_key=secret_data[secret_key_field],
        session_token=secret_data.get(session_token_field),
        region=secret_data.get(region_field) or region_name
    )


def assume_role_session(
    role_arn: str,
    role_session_name: str,
    external_id: Optional[str] = None,
    duration_seconds: int = 3600,
    region_name: Optional[str] = None,
    base_session: Optional[boto3.Session] = None,
) -> boto3.Session:
    """
    Crear una sesión asumiendo un rol IAM.
    
    Args:
        role_arn: ARN del rol a asumir
        role_session_name: Nombre para la sesión
        external_id: ID externo para la asunción del rol
        duration_seconds: Duración de las credenciales temporales (1-12 horas)
        region_name: Región AWS a usar
        base_session: Sesión base para hacer AssumeRole (opcional)
        
    Returns:
        boto3.Session: Sesión con las credenciales del rol asumido
        
    Raises:
        ClientError: Si no se puede asumir el rol
    """
    if not role_arn:
        raise ValueError("Se requiere role_arn para asumir un rol")
    
    # Usar sesión base o crear una nueva
    if base_session:
        sts = base_session.client("sts")
    else:
        sts = boto3.client("sts", region_name=region_name)
    
    # Preparar parámetros para AssumeRole
    assume_role_params = {
        "RoleArn": role_arn,
        "RoleSessionName": role_session_name,
        "DurationSeconds": duration_seconds,
    }
    
    if external_id:
        assume_role_params["ExternalId"] = external_id
    
    try:
        # Asumir el rol
        response = sts.assume_role(**assume_role_params)
        
        # Extraer credenciales temporales
        credentials = response["Credentials"]
        
        # Crear nueva sesión con las credenciales asumidas
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region_name
        )
        
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDenied":
            raise PermissionError(f"Acceso denegado al asumir rol {role_arn}") from e
        else:
            raise


def get_credentials_provider(
    credentials: Optional[AWSCredentials] = None,
    role_arn: Optional[str] = None,
    secret_name: Optional[str] = None,
    profile_name: Optional[str] = None,
) -> CredentialProvider:
    """
    Detectar automáticamente el proveedor de credenciales basado en los parámetros.
    
    Args:
        credentials: Credenciales directas
        role_arn: ARN de rol para AssumeRole
        secret_name: Nombre de secreto en Secrets Manager
        profile_name: Nombre de perfil AWS
        
    Returns:
        CredentialProvider: Tipo de proveedor detectado
        
    Raises:
        ValueError: Si no se puede determinar el proveedor
    """
    return _detect_credential_provider(
        credentials=credentials,
        role_arn=role_arn,
        secret_name=secret_name,
        profile_name=profile_name
    )


def validate_credentials(
    session: Optional[boto3.Session] = None,
    credentials: Optional[AWSCredentials] = None,
    provider: Optional[CredentialProvider] = None,
    **kwargs
) -> bool:
    """
    Validar que las credenciales AWS funcionen correctamente.
    
    Args:
        session: Sesión boto3 existente a validar
        credentials: Credenciales a validar
        provider: Proveedor de credenciales a usar
        **kwargs: Argumentos adicionales para get_boto3_session
        
    Returns:
        bool: True si las credenciales son válidas, False en caso contrario
    """
    try:
        # Obtener sesión si no se proporciona
        if not session:
            if credentials:
                session = boto3.Session(**credentials.to_dict())
            else:
                session = get_boto3_session(provider=provider, credentials=credentials, **kwargs)
        
        # Intentar una operación simple con STS
        sts = session.client("sts")
        response = sts.get_caller_identity()
        
        # Si llegamos aquí, las credenciales son válidas
        return bool(response.get("Account"))
        
    except (NoCredentialsError, ClientError):
        return False
    except Exception:
        # Cualquier otro error también indica credenciales inválidas
        return False


def _detect_credential_provider(
    credentials: Optional[AWSCredentials] = None,
    role_arn: Optional[str] = None,
    secret_name: Optional[str] = None,
    profile_name: Optional[str] = None,
) -> CredentialProvider:
    """
    Función interna para detectar el proveedor de credenciales.
    
    Prioridad:
    1. Credenciales directas
    2. Secrets Manager
    3. AssumeRole
    4. Perfil de configuración
    5. Variables de entorno
    6. Instance profile
    """
    if credentials:
        return CredentialProvider.DIRECT
    elif secret_name:
        return CredentialProvider.SECRETS_MANAGER
    elif role_arn:
        return CredentialProvider.ASSUME_ROLE
    elif profile_name:
        return CredentialProvider.CONFIG_FILE
    elif os.environ.get("AWS_ACCESS_KEY_ID"):
        return CredentialProvider.ENVIRONMENT
    else:
        # Intentar detectar si estamos en EC2/ECS/Lambda
        try:
            # En EC2/ECS, esta variable suele estar presente
            if os.environ.get("AWS_EXECUTION_ENV") or os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
                return CredentialProvider.INSTANCE_PROFILE
        except:
            pass
        
        # Por defecto, intentar instance profile
        return CredentialProvider.INSTANCE_PROFILE