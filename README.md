# Python Helpers

Una colección de utilidades y helpers de Python reutilizables para proyectos diversos.

## 📦 Instalación

```bash
# Usando pip
pip install -e .

# Usando uv (recomendado)
uv pip install -e .
```

## 🚀 Estructura del Proyecto

```
python-helpers/
├── custom_auth/
│   └── middleware.py      # Middleware de autenticación para APIs
├── custom_aws/
│   ├── secrets.py         # Utilidades para AWS Secrets Manager
│   ├── sqs.py             # Utilidades para Amazon SQS
│   └── sns.py             # Utilidades para Amazon SNS
├── pyproject.toml         # Configuración del proyecto
└── README.md             # Este archivo
```

## 📚 Módulos Disponibles

> 📖 **[Ver documentación completa](docs/index.md)** para guías detalladas de cada módulo.

### 🔐 Custom Auth
**`custom_auth.middleware`** - Middleware de autenticación por API key para aplicaciones Starlette/FastAPI

```python
# Opción 1: Middleware global para toda la aplicación
from custom_auth.middleware import create_authentication_middleware

middleware = create_authentication_middleware(api_key="tu-api-key-secreta")

# Opción 2: Verificador para endpoints específicos (FastAPI)
from fastapi import Depends
from custom_auth.middleware import create_api_key_verifier

verify_api_key = create_api_key_verifier("tu-api-key-secreta")

@app.get("/protected")
async def protected_endpoint(verified: None = Depends(verify_api_key)):
    return {"data": "sensitive"}
```

### ☁️ Custom AWS
#### AWS Credentials
**`custom_aws.credentials`** - Gestión flexible de credenciales AWS con múltiples proveedores

```python
from custom_aws.credentials import get_boto3_session, CredentialProvider

# Usar diferentes proveedores de credenciales
session = get_boto3_session(provider=CredentialProvider.ENVIRONMENT)
s3 = session.client('s3')

# AssumeRole
session = get_boto3_session(
    provider=CredentialProvider.ASSUME_ROLE,
    role_arn="arn:aws:iam::123456789012:role/MyRole",
    role_session_name="mi-sesion"
)
```

#### AWS Secrets Manager
**`custom_aws.secrets`** - Utilidades para trabajar con AWS Secrets Manager

```python
from custom_aws.secrets import get_secret_fields

# Obtener campos específicos de un secreto
config = get_secret_fields(
    secret_name="mi-app/config",
    fields=["api_key", "endpoint"],
    region_name="eu-west-1"
)
```

#### Amazon SQS
**`custom_aws.sqs`** - Utilidades para enviar y recibir mensajes en colas SQS

```python
from custom_aws.sqs import send_message, receive_messages, delete_message

# Enviar un mensaje
response = send_message(
    "https://sqs.eu-west-1.amazonaws.com/123456789/mi-cola",
    {"tipo": "pedido", "id": 123}
)

# Recibir y procesar mensajes
messages = receive_messages("queue_url", max_messages=10)
for msg in messages:
    print(f"Procesando: {msg['Body']}")
    # Eliminar mensaje después de procesar
    delete_message("queue_url", msg['ReceiptHandle'])
```

#### Amazon SNS
**`custom_aws.sns`** - Utilidades para publicar notificaciones y gestionar suscripciones SNS

```python
from custom_aws.sns import publish_message, subscribe, list_subscriptions_by_topic

# Publicar un mensaje a un tópico
response = publish_message(
    topic_arn="arn:aws:sns:eu-west-1:123456789:alertas",
    message="Notificación importante",
    subject="Alerta del sistema"
)

# Enviar SMS directo
publish_message(
    phone_number="+34600123456",
    message="Tu código de verificación es: 1234"
)

# Suscribir un email al tópico
subscribe(
    topic_arn="arn:aws:sns:eu-west-1:123456789:alertas",
    protocol="email",
    endpoint="usuario@ejemplo.com"
)
```


## 🛠️ Desarrollo

### Configurar entorno de desarrollo

```bash
# Clonar el repositorio
git clone <repo-url>
cd python-helpers

# Instalar dependencias con uv
uv sync

# O con pip
pip install -e ".[dev]"
```

### Ejecutar tests

#### Usando Make (recomendado)

```bash
# Ver todos los comandos disponibles
make help

# Instalar dependencias de desarrollo
make install-dev

# Ejecutar todos los tests
make test

# Ejecutar con cobertura
make test-coverage

# Ejecutar tests específicos
make test-unit          # Solo tests unitarios
make test-integration   # Solo tests de integración
make test-custom-auth   # Tests del módulo custom_auth
make test-custom-aws    # Tests del módulo custom_aws

# Otros comandos útiles
make clean              # Limpiar archivos temporales
make check              # Ejecutar lint, type-check y tests
make pre-commit         # Verificaciones antes de commit
```

#### Usando comandos directos

```bash
# Instalar dependencias de desarrollo
uv pip install -e ".[dev]"

# Ejecutar todos los tests
uv run pytest

# Ejecutar con cobertura
uv run pytest --cov=. --cov-report=html

# Ejecutar tests de un módulo específico
uv run pytest tests/custom_auth/
uv run pytest tests/custom_aws/


# Ejecutar un archivo de test específico
uv run pytest tests/custom_aws/test_secrets.py

# Ejecutar una función de test específica
uv run pytest tests/custom_aws/test_secrets.py::TestParseSecretJson::test_parse_with_required_fields_success

# Ejecutar por marcadores
uv run pytest -m unit        # Solo tests unitarios
uv run pytest -m integration # Solo tests de integración
uv run pytest -m "not slow"  # Excluir tests lentos
```

## 🤝 Contribuir

1. Fork el proyecto
2. Crea tu feature branch (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Add: nueva funcionalidad'`)
4. Push a la branch (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

## 📝 Principios de Desarrollo

Este proyecto sigue los principios SOLID:
- **S**ingle Responsibility: Cada módulo tiene una responsabilidad única
- **O**pen/Closed: Abierto para extensión, cerrado para modificación
- **L**iskov Substitution: Las implementaciones son intercambiables
- **I**nterface Segregation: Interfaces específicas y enfocadas
- **D**ependency Inversion: Dependencias mediante abstracciones

## 📄 Licencia

Este proyecto es privado y de uso interno.