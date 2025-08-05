# AWS Credentials - Gestión de Credenciales AWS

El módulo `custom_aws.credentials` proporciona utilidades para gestionar credenciales AWS de manera flexible y segura, soportando múltiples métodos de autenticación.

## Características

- 🔐 **Múltiples proveedores**: Credenciales directas, AssumeRole, Secrets Manager, variables de entorno, perfiles e instance profiles
- 🔄 **Detección automática**: Detecta el mejor método de autenticación disponible
- ✅ **Validación**: Verifica que las credenciales funcionen antes de usarlas
- 🛡️ **Seguro**: Manejo adecuado de secretos y credenciales temporales
- 🔧 **Flexible**: Fácil integración con diferentes entornos y casos de uso

## Instalación

```python
from custom_aws.credentials import (
    CredentialProvider,
    AWSCredentials,
    get_boto3_session,
    get_client_with_credentials,
    get_credentials_from_secret,
    assume_role_session,
    validate_credentials,
)
```

## Proveedores de Credenciales

### 1. Credenciales Directas

```python
from custom_aws.credentials import AWSCredentials, get_boto3_session, CredentialProvider

# Crear credenciales
creds = AWSCredentials(
    access_key_id="AKIAIOSFODNN7EXAMPLE",
    secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    session_token="token_opcional",  # Opcional, para credenciales temporales
    region="eu-west-1"  # Opcional
)

# Crear sesión
session = get_boto3_session(
    provider=CredentialProvider.DIRECT,
    credentials=creds
)

# Usar la sesión
s3 = session.client('s3')
```

### 2. AssumeRole (STS)

```python
# Asumir un rol IAM
session = get_boto3_session(
    provider=CredentialProvider.ASSUME_ROLE,
    role_arn="arn:aws:iam::123456789012:role/MyRole",
    role_session_name="mi-sesion",
    external_id="id-externo-opcional",  # Opcional
    region_name="us-east-1"
)

# O usar la función directa
from custom_aws.credentials import assume_role_session

session = assume_role_session(
    role_arn="arn:aws:iam::123456789012:role/MyRole",
    role_session_name="mi-sesion",
    external_id="id-externo",
    duration_seconds=7200,  # 2 horas (máximo 12 horas)
    region_name="us-east-1"
)
```

### 3. AWS Secrets Manager

```python
# Obtener credenciales desde un secreto
session = get_boto3_session(
    provider=CredentialProvider.SECRETS_MANAGER,
    secret_name="mi-app/credenciales-aws",
    region_name="eu-west-1"
)

# O usar la función directa
from custom_aws.credentials import get_credentials_from_secret

creds = get_credentials_from_secret(
    secret_name="mi-app/credenciales-aws",
    region_name="eu-west-1"
)

# Con campos personalizados en el secreto
creds = get_credentials_from_secret(
    secret_name="mi-app/config",
    access_key_field="aws_access_key",  # Default: "access_key_id"
    secret_key_field="aws_secret_key",  # Default: "secret_access_key"
    session_token_field="aws_token",    # Default: "session_token"
    region_field="aws_region"            # Default: "region"
)
```

### 4. Variables de Entorno

```python
# Usar credenciales de variables de entorno
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, etc.
session = get_boto3_session(
    provider=CredentialProvider.ENVIRONMENT,
    region_name="us-west-2"
)
```

### 5. Archivo de Configuración

```python
# Usar perfil de ~/.aws/credentials
session = get_boto3_session(
    provider=CredentialProvider.CONFIG_FILE,
    profile_name="mi-perfil",
    region_name="ap-southeast-1"
)
```

### 6. Instance Profile (EC2/ECS/Lambda)

```python
# Usar credenciales del instance profile
session = get_boto3_session(
    provider=CredentialProvider.INSTANCE_PROFILE,
    region_name="us-east-1"
)
```

## Detección Automática

Si no especificas un proveedor, el módulo detectará automáticamente el mejor método disponible:

```python
# Detección automática basada en parámetros
session = get_boto3_session(
    role_arn="arn:aws:iam::123456789012:role/MyRole",
    role_session_name="auto-session"
)
# Detecta: ASSUME_ROLE

session = get_boto3_session(secret_name="mi-secreto")
# Detecta: SECRETS_MANAGER

session = get_boto3_session()
# Detecta: ENVIRONMENT o INSTANCE_PROFILE según el entorno
```

## Crear Clientes AWS

```python
from custom_aws.credentials import get_client_with_credentials

# Crear cliente S3 con credenciales específicas
s3_client = get_client_with_credentials(
    "s3",
    provider=CredentialProvider.ASSUME_ROLE,
    role_arn="arn:aws:iam::123456789012:role/S3ReadOnlyRole",
    role_session_name="s3-reader"
)

# Crear cliente EC2 con secreto
ec2_client = get_client_with_credentials(
    "ec2",
    provider=CredentialProvider.SECRETS_MANAGER,
    secret_name="ec2-admin-credentials",
    region_name="eu-central-1"
)
```

## Validación de Credenciales

```python
from custom_aws.credentials import validate_credentials

# Validar sesión existente
session = get_boto3_session(profile_name="mi-perfil")
if validate_credentials(session=session):
    print("✅ Credenciales válidas")
else:
    print("❌ Credenciales inválidas")

# Validar credenciales específicas
creds = AWSCredentials(
    access_key_id="AKIAIOSFODNN7EXAMPLE",
    secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)
if validate_credentials(credentials=creds):
    print("✅ Credenciales válidas")

# Validar con proveedor
if validate_credentials(
    provider=CredentialProvider.ENVIRONMENT,
    region_name="us-east-1"
):
    print("✅ Variables de entorno configuradas correctamente")
```

## Ejemplos de Uso Completos

### Ejemplo 1: Aplicación con Múltiples Cuentas AWS

```python
from custom_aws.credentials import get_client_with_credentials, CredentialProvider

class MultiAccountManager:
    def __init__(self):
        # Cliente para cuenta de producción
        self.prod_s3 = get_client_with_credentials(
            "s3",
            provider=CredentialProvider.ASSUME_ROLE,
            role_arn="arn:aws:iam::111111111111:role/ProdAccess",
            role_session_name="prod-manager"
        )
        
        # Cliente para cuenta de desarrollo
        self.dev_s3 = get_client_with_credentials(
            "s3",
            provider=CredentialProvider.ASSUME_ROLE,
            role_arn="arn:aws:iam::222222222222:role/DevAccess",
            role_session_name="dev-manager"
        )
        
        # Cliente para cuenta de auditoría (solo lectura)
        self.audit_s3 = get_client_with_credentials(
            "s3",
            provider=CredentialProvider.SECRETS_MANAGER,
            secret_name="audit-account-readonly"
        )
    
    def list_all_buckets(self):
        """Listar buckets en todas las cuentas."""
        buckets = {}
        
        buckets['prod'] = self.prod_s3.list_buckets()['Buckets']
        buckets['dev'] = self.dev_s3.list_buckets()['Buckets']
        buckets['audit'] = self.audit_s3.list_buckets()['Buckets']
        
        return buckets
```

### Ejemplo 2: Rotación Automática de Credenciales

```python
import time
from custom_aws.credentials import (
    get_credentials_from_secret,
    validate_credentials,
    get_boto3_session
)

class RotatingCredentialsClient:
    def __init__(self, secret_name, service_name):
        self.secret_name = secret_name
        self.service_name = service_name
        self._session = None
        self._client = None
        self._last_refresh = 0
        self.refresh_interval = 3600  # 1 hora
    
    def _refresh_credentials(self):
        """Refrescar credenciales desde Secrets Manager."""
        creds = get_credentials_from_secret(self.secret_name)
        
        # Validar antes de usar
        if not validate_credentials(credentials=creds):
            raise ValueError("Credenciales inválidas en Secrets Manager")
        
        self._session = get_boto3_session(credentials=creds)
        self._client = self._session.client(self.service_name)
        self._last_refresh = time.time()
    
    @property
    def client(self):
        """Obtener cliente, refrescando credenciales si es necesario."""
        if (not self._client or 
            time.time() - self._last_refresh > self.refresh_interval):
            self._refresh_credentials()
        return self._client

# Usar
s3_rotator = RotatingCredentialsClient(
    "prod/s3-credentials",
    "s3"
)

# Las credenciales se refrescan automáticamente
response = s3_rotator.client.list_buckets()
```

### Ejemplo 3: Manejo de Errores Robusto

```python
from custom_aws.credentials import (
    get_boto3_session,
    CredentialProvider,
    validate_credentials
)
from botocore.exceptions import NoCredentialsError, ClientError
import logging

logger = logging.getLogger(__name__)

def get_aws_session_with_fallback():
    """
    Obtener sesión AWS con múltiples métodos de fallback.
    """
    providers = [
        # Primero intentar con variables de entorno
        (CredentialProvider.ENVIRONMENT, {}),
        
        # Luego perfil específico
        (CredentialProvider.CONFIG_FILE, {"profile_name": "default"}),
        
        # Luego instance profile (EC2/ECS)
        (CredentialProvider.INSTANCE_PROFILE, {}),
        
        # Finalmente, credenciales de emergencia en Secrets Manager
        (CredentialProvider.SECRETS_MANAGER, {
            "secret_name": "emergency-credentials"
        }),
    ]
    
    for provider, kwargs in providers:
        try:
            session = get_boto3_session(provider=provider, **kwargs)
            
            # Validar que funcionen
            if validate_credentials(session=session):
                logger.info(f"✅ Usando proveedor: {provider.value}")
                return session
            else:
                logger.warning(f"⚠️ Credenciales inválidas para: {provider.value}")
                
        except (NoCredentialsError, ClientError, ValueError) as e:
            logger.warning(f"❌ Fallo con proveedor {provider.value}: {e}")
            continue
    
    raise RuntimeError("No se pudieron obtener credenciales AWS válidas")

# Usar
try:
    session = get_aws_session_with_fallback()
    s3 = session.client('s3')
    buckets = s3.list_buckets()
    print(f"Encontrados {len(buckets['Buckets'])} buckets")
except RuntimeError as e:
    logger.error(f"Error crítico: {e}")
```

### Ejemplo 4: Integración con FastAPI

```python
from fastapi import FastAPI, Depends, HTTPException
from functools import lru_cache
from custom_aws.credentials import (
    get_client_with_credentials,
    CredentialProvider,
    validate_credentials
)

app = FastAPI()

@lru_cache()
def get_s3_client():
    """Obtener cliente S3 singleton."""
    try:
        client = get_client_with_credentials(
            "s3",
            provider=CredentialProvider.INSTANCE_PROFILE
        )
        
        # Validar al inicio
        session = client._client_config.__dict__.get('_user_provided_options', {})
        if not validate_credentials():
            raise ValueError("Credenciales inválidas")
            
        return client
    except Exception as e:
        raise HTTPException(500, f"Error configurando AWS: {e}")

@app.get("/buckets")
async def list_buckets(s3=Depends(get_s3_client)):
    """Listar todos los buckets S3."""
    try:
        response = s3.list_buckets()
        return {
            "buckets": [b['Name'] for b in response['Buckets']],
            "count": len(response['Buckets'])
        }
    except Exception as e:
        raise HTTPException(500, f"Error listando buckets: {e}")

@app.on_event("startup")
async def startup_event():
    """Validar credenciales al iniciar."""
    try:
        get_s3_client()
        print("✅ Credenciales AWS validadas")
    except Exception as e:
        print(f"❌ Error con credenciales AWS: {e}")
        raise
```

## Mejores Prácticas

### 1. Seguridad

- **Nunca hardcodees credenciales** en el código
- Usa **Secrets Manager** o **variables de entorno** para credenciales sensibles
- Implementa **rotación regular** de credenciales
- Usa **AssumeRole** con permisos mínimos necesarios

### 2. Performance

```python
from functools import lru_cache

@lru_cache(maxsize=10)
def get_cached_session(provider_name: str, **kwargs):
    """Cache de sesiones por proveedor."""
    provider = CredentialProvider(provider_name)
    return get_boto3_session(provider=provider, **kwargs)
```

### 3. Logging

```python
import logging
from custom_aws.credentials import get_boto3_session

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_session_with_logging(**kwargs):
    """Obtener sesión con logging detallado."""
    try:
        logger.info("Obteniendo credenciales AWS...")
        session = get_boto3_session(**kwargs)
        
        # Log información básica (sin secretos)
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        logger.info(f"✅ Autenticado como: {identity['Arn']}")
        
        return session
    except Exception as e:
        logger.error(f"❌ Error obteniendo credenciales: {e}")
        raise
```

### 4. Testing

```python
from unittest.mock import patch, Mock
from custom_aws.credentials import get_boto3_session, CredentialProvider

@patch('boto3.Session')
def test_my_function(mock_session):
    """Test con credenciales mockeadas."""
    # Configurar mock
    mock_client = Mock()
    mock_session.return_value.client.return_value = mock_client
    
    # Tu código que usa credenciales
    session = get_boto3_session(
        provider=CredentialProvider.DIRECT,
        credentials=Mock()
    )
    
    # Verificar
    assert mock_session.called
```

## Solución de Problemas

### Error: "No credentials found"

```python
# Verificar qué proveedores están disponibles
from custom_aws.credentials import get_credentials_provider, validate_credentials

# Detectar proveedor
provider = get_credentials_provider()
print(f"Proveedor detectado: {provider.value}")

# Validar
if not validate_credentials(provider=provider):
    print("❌ Credenciales no válidas")
    
    # Verificar configuración
    import os
    print(f"AWS_ACCESS_KEY_ID: {'✅' if os.environ.get('AWS_ACCESS_KEY_ID') else '❌'}")
    print(f"AWS_PROFILE: {os.environ.get('AWS_PROFILE', 'No configurado')}")
```

### Error: "Access Denied"

```python
# Verificar identidad y permisos
from custom_aws.credentials import get_boto3_session

session = get_boto3_session()
sts = session.client('sts')

try:
    identity = sts.get_caller_identity()
    print(f"Account: {identity['Account']}")
    print(f"ARN: {identity['Arn']}")
    print(f"UserID: {identity['UserId']}")
except Exception as e:
    print(f"Error verificando identidad: {e}")
```

## Referencias

- [Documentación de boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [AWS Credentials Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AssumeRole Documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)