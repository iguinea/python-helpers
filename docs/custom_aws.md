# Custom AWS Module

## Descripción General

El módulo `custom_aws` proporciona utilidades para interactuar con servicios de AWS, incluyendo AWS Secrets Manager, Amazon SQS y Amazon SNS. Facilita la recuperación segura de credenciales, configuraciones almacenadas en la nube, el manejo de mensajes en colas y la publicación de notificaciones.

## Instalación

```python
# AWS Secrets Manager
from custom_aws.secrets import get_secret_fields, parse_secret_json, check_secrets_manager_connection

# Amazon SQS
from custom_aws.sqs import send_message, receive_messages, delete_message

# Amazon SNS
from custom_aws.sns import publish_message, subscribe, unsubscribe

```

## Servicios Disponibles

### AWS Secrets Manager

Para gestión segura de credenciales y configuraciones. [Ver documentación completa de Secrets Manager](./custom_aws.md#aws-secrets-manager)

### Amazon SQS

Para manejo de mensajes en colas. [Ver documentación completa de SQS](./custom_aws_sqs.md)

### Amazon SNS

Para publicación de notificaciones y gestión de suscripciones. [Ver documentación completa de SNS](./custom_aws_sns.md)


## AWS Secrets Manager

### get_secret_fields

Recupera campos específicos de un secreto JSON almacenado en AWS Secrets Manager.

```python
def get_secret_fields(
    secret_name: str,
    fields: list[str],
    region_name: Optional[str] = None,
    allow_missing: bool = False
) -> Dict[str, Any]
```

**Parámetros:**
- `secret_name`: Nombre o ARN del secreto en AWS Secrets Manager
- `fields`: Lista de campos a recuperar del secreto
- `region_name`: Región de AWS (opcional, por defecto usa la variable de entorno)
- `allow_missing`: Si True, ignora campos faltantes. Si False, lanza error

**Retorna:**
- Diccionario con los campos solicitados y sus valores

**Excepciones:**
- `ValueError`: Si el secreto no es JSON, la lista de campos está vacía, o faltan campos requeridos
- `ClientError`: Para errores de la API de AWS
- `NoCredentialsError`: Si no hay credenciales AWS configuradas

### parse_secret_json

Parsea un secreto JSON y valida campos requeridos.

```python
def parse_secret_json(
    secret_value: str,
    required_fields: Optional[list[str]] = None
) -> Dict[str, Any]
```

**Parámetros:**
- `secret_value`: String del secreto a parsear
- `required_fields`: Lista de campos que deben estar presentes

**Retorna:**
- Diccionario con los datos parseados

**Excepciones:**
- `ValueError`: Si el JSON es inválido o faltan campos requeridos

### check_secrets_manager_connection

Verifica que AWS Secrets Manager sea accesible.

```python
def check_secrets_manager_connection(
    region_name: Optional[str] = None
) -> bool
```

**Parámetros:**
- `region_name`: Región AWS a probar (opcional)

**Retorna:**
- `True` si la conexión es exitosa, `False` en caso contrario

## Configuración de AWS

### Credenciales

Las credenciales de AWS se pueden configurar de varias formas:

1. **Variables de Entorno**
   ```bash
   export AWS_ACCESS_KEY_ID=your-access-key
   export AWS_SECRET_ACCESS_KEY=your-secret-key
   export AWS_DEFAULT_REGION=eu-west-1
   ```

2. **Archivo de Credenciales** (`~/.aws/credentials`)
   ```ini
   [default]
   aws_access_key_id = your-access-key
   aws_secret_access_key = your-secret-key
   ```

3. **IAM Role** (recomendado para producción)
   - En EC2, ECS, Lambda, etc., usa roles IAM en lugar de credenciales

### Permisos IAM Requeridos

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue",
                "secretsmanager:ListSecrets"
            ],
            "Resource": "*"
        }
    ]
}
```

## Ejemplos de Uso

### Recuperar Configuración de Aplicación

```python
from custom_aws.secrets import get_secret_fields

# Recuperar configuración de base de datos
db_config = get_secret_fields(
    secret_name="myapp/database",
    fields=["host", "port", "username", "password", "database"],
    region_name="eu-west-1"
)

# Usar la configuración
connection_string = f"postgresql://{db_config['username']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['database']}"
```

### Manejo de Campos Opcionales

```python
# Permitir campos faltantes
config = get_secret_fields(
    secret_name="myapp/config",
    fields=["api_key", "timeout", "optional_feature"],
    allow_missing=True
)

# Verificar si un campo opcional existe
if "optional_feature" in config:
    enable_feature(config["optional_feature"])
```

### Verificar Conexión

```python
from custom_aws.secrets import check_secrets_manager_connection

# Verificar conexión antes de usar
if check_secrets_manager_connection():
    print("✅ Conexión a AWS Secrets Manager exitosa")
    # Proceder con operaciones
else:
    print("❌ No se puede conectar a AWS Secrets Manager")
    # Usar configuración local o fallar
```

### Manejo de Errores

```python
from custom_aws.secrets import get_secret_fields
from botocore.exceptions import ClientError, NoCredentialsError

try:
    config = get_secret_fields(
        secret_name="myapp/config",
        fields=["api_key", "endpoint"]
    )
except NoCredentialsError:
    print("Error: No se encontraron credenciales AWS")
    # Usar configuración local
except ValueError as e:
    if "not found" in str(e):
        print(f"Error: El secreto no existe: {e}")
    elif "missing fields" in str(e):
        print(f"Error: Faltan campos requeridos: {e}")
    else:
        print(f"Error de validación: {e}")
except PermissionError as e:
    print(f"Error: Sin permisos para acceder al secreto: {e}")
except ClientError as e:
    print(f"Error de AWS: {e}")
```

## Formato de Secretos

Los secretos deben estar almacenados como JSON válido:

```json
{
    "api_key": "sk-1234567890abcdef",
    "endpoint": "https://api.example.com",
    "timeout": 30,
    "features": {
        "feature_a": true,
        "feature_b": false
    }
}
```

### Secretos Anidados

Para acceder a valores anidados, recupera el objeto completo:

```python
# Recuperar todo el objeto features
config = get_secret_fields(
    secret_name="myapp/config",
    fields=["features"]
)

# Acceder a valores anidados
if config["features"]["feature_a"]:
    enable_feature_a()
```

## Mejores Prácticas

1. **Cacheo de Secretos**
   ```python
   from functools import lru_cache
   
   @lru_cache(maxsize=10)
   def get_cached_secret(secret_name: str, fields: tuple) -> dict:
       return get_secret_fields(secret_name, list(fields))
   
   # Usar tupla para fields porque lru_cache requiere argumentos hashables
   config = get_cached_secret("myapp/config", ("api_key", "endpoint"))
   ```

2. **Rotación de Secretos**
   - AWS Secrets Manager soporta rotación automática
   - Diseña tu aplicación para recargar secretos periódicamente
   - No caches secretos por más de 1 hora

3. **Organización de Secretos**
   ```
   proyecto/
   ├── desarrollo/
   │   ├── database
   │   └── api-keys
   ├── staging/
   │   ├── database
   │   └── api-keys
   └── produccion/
       ├── database
       └── api-keys
   ```

4. **Separación de Ambientes**
   ```python
   import os
   
   environment = os.environ.get("ENVIRONMENT", "desarrollo")
   secret_name = f"myapp/{environment}/database"
   
   db_config = get_secret_fields(secret_name, ["host", "username", "password"])
   ```

## Testing

### Mock para Pruebas

```python
import pytest
from unittest.mock import patch, MagicMock
from custom_aws.secrets import get_secret_fields

@patch('boto3.Session')
def test_get_secret_fields(mock_session):
    # Configurar mock
    mock_client = MagicMock()
    mock_session.return_value.client.return_value = mock_client
    
    mock_client.get_secret_value.return_value = {
        'SecretString': '{"api_key": "test-key", "endpoint": "http://test.com"}'
    }
    
    # Ejecutar
    result = get_secret_fields(
        "test-secret",
        ["api_key", "endpoint"]
    )
    
    # Verificar
    assert result["api_key"] == "test-key"
    assert result["endpoint"] == "http://test.com"
```

### Usando Moto para Tests de Integración

```python
import pytest
import boto3
from moto import mock_aws
import json

@mock_aws
def test_integration_with_moto():
    # Crear cliente mock
    client = boto3.client("secretsmanager", region_name="us-east-1")
    
    # Crear secreto
    secret_data = {"api_key": "test-123", "endpoint": "https://api.test.com"}
    client.create_secret(
        Name="test-secret",
        SecretString=json.dumps(secret_data)
    )
    
    # Probar función
    from custom_aws.secrets import get_secret_fields
    result = get_secret_fields("test-secret", ["api_key"])
    
    assert result["api_key"] == "test-123"
```

## Troubleshooting

### Error: "The security token included in the request is invalid"
- Verifica que las credenciales AWS sean válidas
- Si usas MFA, asegúrate de que el token de sesión esté actualizado

### Error: "Secret not found"
- Verifica el nombre exacto del secreto
- Confirma la región correcta
- Asegúrate de tener permisos para listar secretos

### Error: "Access denied"
- Revisa los permisos IAM
- Verifica que el rol/usuario tenga `secretsmanager:GetSecretValue`
- Si el secreto está encriptado con KMS, necesitas permisos KMS también

### Conexión lenta o timeouts
- Considera usar un endpoint VPC para Secrets Manager
- Verifica la conectividad de red desde tu aplicación a AWS