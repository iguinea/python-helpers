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
    from starlette.routing import Route
    from starlette.responses import JSONResponse
    
    async def homepage(request):
        return JSONResponse({"message": "Hello, World!"})
    
    async def health(request):
        return JSONResponse({"status": "healthy"})
    
    async def protected(request):
        return JSONResponse({"message": "Protected resource"})
    
    routes = [
        Route("/", endpoint=homepage),
        Route("/health", endpoint=health),
        Route("/protected", endpoint=protected),
    ]
    
    app = Starlette(routes=routes)
    return app


@pytest.fixture
def test_client(starlette_app):
    """Cliente de prueba para Starlette."""
    return TestClient(starlette_app)




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