"""
Configuración compartida de pytest y fixtures comunes.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
import pytest
import boto3
from moto import mock_aws
from starlette.applications import Starlette
from starlette.testclient import TestClient

# Agregar el directorio raíz al path para importaciones
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def temp_dir():
    """Crea un directorio temporal para pruebas."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def temp_log_file(temp_dir):
    """Crea un archivo temporal para logs."""
    return os.path.join(temp_dir, "test.log")


@pytest.fixture
def mock_aws_credentials():
    """Mock de credenciales AWS para pruebas."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    yield
    # Limpiar variables de entorno
    for key in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", 
                "AWS_SECURITY_TOKEN", "AWS_SESSION_TOKEN"]:
        os.environ.pop(key, None)


@pytest.fixture
def mock_secrets_manager(mock_aws_credentials):
    """Mock de AWS Secrets Manager."""
    with mock_aws():
        yield boto3.client("secretsmanager", region_name="us-east-1")


@pytest.fixture
def starlette_app():
    """Crea una aplicación Starlette básica para pruebas."""
    app = Starlette()
    
    @app.route("/")
    async def homepage(request):
        return {"message": "Hello, World!"}
    
    @app.route("/health")
    async def health(request):
        return {"status": "healthy"}
    
    @app.route("/protected")
    async def protected(request):
        return {"message": "Protected resource"}
    
    return app


@pytest.fixture
def test_client(starlette_app):
    """Cliente de prueba para Starlette."""
    return TestClient(starlette_app)


@pytest.fixture
def sample_json_schema():
    """Esquema JSON de ejemplo para pruebas de validación."""
    return {
        "type": "object",
        "required": ["name", "age"],
        "properties": {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 100
            },
            "age": {
                "type": "integer",
                "minimum": 0,
                "maximum": 150
            },
            "email": {
                "type": "string",
                "pattern": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 0,
                "maxItems": 10
            }
        },
        "additionalProperties": False
    }


@pytest.fixture
def valid_test_data():
    """Datos de prueba válidos para validación."""
    return {
        "name": "Juan Pérez",
        "age": 30,
        "email": "juan@example.com",
        "tags": ["python", "testing"]
    }


# Marcadores personalizados
def pytest_configure(config):
    """Configurar marcadores personalizados de pytest."""
    config.addinivalue_line(
        "markers", "unit: marca las pruebas como pruebas unitarias"
    )
    config.addinivalue_line(
        "markers", "integration: marca las pruebas como pruebas de integración"
    )
    config.addinivalue_line(
        "markers", "slow: marca las pruebas que tardan más tiempo en ejecutarse"
    )