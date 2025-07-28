"""
Tests para el módulo auth.middleware
"""

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient
from starlette.responses import JSONResponse
from starlette.middleware import Middleware

from auth.middleware import APIKeyAuthMiddleware, create_authentication_middleware


class TestAPIKeyAuthMiddleware:
    """Tests para APIKeyAuthMiddleware"""
    
    @pytest.fixture
    def api_key(self):
        """API key de prueba."""
        return "test-api-key-12345"
    
    @pytest.fixture
    def app_with_middleware(self, api_key):
        """Aplicación Starlette con middleware de autenticación."""
        app = Starlette(
            middleware=[
                Middleware(
                    APIKeyAuthMiddleware,
                    api_key=api_key,
                    unauthenticated_paths=["/health", "/ping"]
                )
            ]
        )
        
        @app.route("/")
        async def homepage(request):
            return JSONResponse({"message": "Home page"})
        
        @app.route("/health")
        async def health(request):
            return JSONResponse({"status": "healthy"})
        
        @app.route("/protected")
        async def protected(request):
            return JSONResponse({"message": "Protected resource"})
        
        return TestClient(app)
    
    @pytest.mark.unit
    def test_middleware_initialization_without_api_key(self):
        """Test que el middleware lanza error sin API key."""
        app = Starlette()
        
        with pytest.raises(ValueError, match="API key must be provided"):
            APIKeyAuthMiddleware(app, api_key="")
    
    @pytest.mark.unit
    def test_unauthenticated_paths_bypass(self, app_with_middleware):
        """Test que las rutas no autenticadas se pueden acceder sin API key."""
        response = app_with_middleware.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}
    
    @pytest.mark.unit
    def test_missing_api_key_returns_401(self, app_with_middleware):
        """Test que las rutas protegidas devuelven 401 sin API key."""
        response = app_with_middleware.get("/protected")
        assert response.status_code == 401
        assert response.json()["error"] == "API key required"
        assert "Please provide API key" in response.json()["message"]
    
    @pytest.mark.unit
    def test_invalid_api_key_returns_403(self, app_with_middleware):
        """Test que una API key inválida devuelve 403."""
        response = app_with_middleware.get(
            "/protected",
            headers={"X-API-Key": "invalid-key"}
        )
        assert response.status_code == 403
        assert response.json()["error"] == "Invalid API key"
    
    @pytest.mark.unit
    def test_valid_api_key_via_bearer_token(self, app_with_middleware, api_key):
        """Test autenticación exitosa con Bearer token."""
        response = app_with_middleware.get(
            "/protected",
            headers={"Authorization": f"Bearer {api_key}"}
        )
        assert response.status_code == 200
        assert response.json() == {"message": "Protected resource"}
    
    @pytest.mark.unit
    def test_valid_api_key_via_x_api_key_header(self, app_with_middleware, api_key):
        """Test autenticación exitosa con header X-API-Key."""
        response = app_with_middleware.get(
            "/protected",
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200
        assert response.json() == {"message": "Protected resource"}
    
    @pytest.mark.unit
    def test_valid_api_key_via_query_parameter(self, app_with_middleware, api_key):
        """Test autenticación exitosa con query parameter."""
        response = app_with_middleware.get(f"/protected?api_key={api_key}")
        assert response.status_code == 200
        assert response.json() == {"message": "Protected resource"}
    
    @pytest.mark.unit
    def test_case_insensitive_headers(self, app_with_middleware, api_key):
        """Test que los headers son case-insensitive."""
        # Test con diferentes capitalizaciones
        response1 = app_with_middleware.get(
            "/protected",
            headers={"x-api-key": api_key}
        )
        assert response1.status_code == 200
        
        response2 = app_with_middleware.get(
            "/protected",
            headers={"X-Api-Key": api_key}
        )
        assert response2.status_code == 200
    
    @pytest.mark.unit
    def test_extract_api_key_priority(self, app_with_middleware, api_key):
        """Test la prioridad de extracción de API key (Bearer > X-API-Key > query)."""
        # Si se proporcionan múltiples, Bearer tiene prioridad
        response = app_with_middleware.get(
            f"/protected?api_key=wrong-key",
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-API-Key": "wrong-key"
            }
        )
        assert response.status_code == 200


class TestCreateAuthenticationMiddleware:
    """Tests para create_authentication_middleware"""
    
    @pytest.mark.unit
    def test_create_middleware_with_api_key(self, capsys):
        """Test creación de middleware con API key."""
        middleware = create_authentication_middleware(
            api_key="test-key",
            unauthenticated_paths=["/health"]
        )
        
        assert middleware is not None
        assert len(middleware) == 1
        
        # Verificar output
        captured = capsys.readouterr()
        assert "✅ API key authentication enabled" in captured.out
        assert "Authorization: Bearer <api_key>" in captured.out
    
    @pytest.mark.unit
    def test_create_middleware_without_api_key(self, capsys):
        """Test creación de middleware sin API key (deshabilitado)."""
        middleware = create_authentication_middleware(api_key=None)
        
        assert middleware == []
        
        # Verificar advertencia
        captured = capsys.readouterr()
        assert "⚠️ Authentication disabled" in captured.out
    
    @pytest.mark.unit
    def test_create_middleware_with_custom_unauthenticated_paths(self):
        """Test creación con paths personalizados."""
        custom_paths = ["/custom", "/open"]
        middleware = create_authentication_middleware(
            api_key="test-key",
            unauthenticated_paths=custom_paths
        )
        
        assert middleware is not None
        # Verificar que se pasaron los paths personalizados
        middleware_instance = middleware[0]
        assert middleware_instance.cls == APIKeyAuthMiddleware
        assert middleware_instance.kwargs["unauthenticated_paths"] == custom_paths
    
    @pytest.mark.integration
    def test_middleware_integration_with_app(self):
        """Test integración completa del middleware con una aplicación."""
        api_key = "integration-test-key"
        
        middleware = create_authentication_middleware(api_key=api_key)
        app = Starlette(middleware=middleware)
        
        @app.route("/data")
        async def get_data(request):
            return JSONResponse({"data": "sensitive"})
        
        client = TestClient(app)
        
        # Sin API key
        response = client.get("/data")
        assert response.status_code == 401
        
        # Con API key válida
        response = client.get("/data", headers={"X-API-Key": api_key})
        assert response.status_code == 200
        assert response.json() == {"data": "sensitive"}