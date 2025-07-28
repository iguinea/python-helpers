"""
Tests para el módulo custom_auth.middleware
"""

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient
from starlette.responses import JSONResponse
from starlette.middleware import Middleware
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient as FastAPITestClient

from custom_auth.middleware import APIKeyAuthMiddleware, create_authentication_middleware, create_api_key_verifier


class TestAPIKeyAuthMiddleware:
    """Tests para APIKeyAuthMiddleware"""
    
    @pytest.fixture
    def api_key(self):
        """API key de prueba."""
        return "test-api-key-12345"
    
    @pytest.fixture
    def app_with_middleware(self, api_key):
        """Aplicación Starlette con middleware de autenticación."""
        from starlette.routing import Route
        
        async def homepage(request):
            return JSONResponse({"message": "Home page"})
        
        async def health(request):
            return JSONResponse({"status": "healthy"})
        
        async def protected(request):
            return JSONResponse({"message": "Protected resource"})
        
        routes = [
            Route("/", endpoint=homepage),
            Route("/health", endpoint=health),
            Route("/protected", endpoint=protected),
        ]
        
        app = Starlette(
            routes=routes,
            middleware=[
                Middleware(
                    APIKeyAuthMiddleware,
                    api_key=api_key,
                    unauthenticated_paths=["/health", "/ping"]
                )
            ]
        )
        
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
        from starlette.routing import Route
        
        api_key = "integration-test-key"
        
        async def get_data(request):
            return JSONResponse({"data": "sensitive"})
        
        routes = [
            Route("/data", endpoint=get_data),
        ]
        
        middleware = create_authentication_middleware(api_key=api_key)
        app = Starlette(routes=routes, middleware=middleware)
        
        client = TestClient(app)
        
        # Sin API key
        response = client.get("/data")
        assert response.status_code == 401
        
        # Con API key válida
        response = client.get("/data", headers={"X-API-Key": api_key})
        assert response.status_code == 200
        assert response.json() == {"data": "sensitive"}


class TestCreateAPIKeyVerifier:
    """Tests para create_api_key_verifier"""
    
    @pytest.fixture
    def api_key(self):
        """API key de prueba."""
        return "test-verifier-key-67890"
    
    @pytest.fixture
    def fastapi_app_with_verifier(self, api_key):
        """Aplicación FastAPI con verificador de API key."""
        app = FastAPI()
        verify_api_key = create_api_key_verifier(api_key)
        
        @app.get("/public")
        async def public_endpoint():
            return {"message": "Public endpoint"}
        
        @app.get("/protected")
        async def protected_endpoint(api_key_verified: None = Depends(verify_api_key)):
            return {"message": "Protected endpoint"}
        
        @app.post("/users")
        async def create_user(
            user_data: dict,
            api_key_verified: None = Depends(verify_api_key)
        ):
            return {"user_id": "123", "data": user_data}
        
        return FastAPITestClient(app)
    
    @pytest.mark.unit
    def test_verifier_creation(self, api_key):
        """Test que el verificador se crea correctamente."""
        verifier = create_api_key_verifier(api_key)
        assert verifier is not None
        assert callable(verifier)
    
    @pytest.mark.unit
    def test_public_endpoint_without_api_key(self, fastapi_app_with_verifier):
        """Test que los endpoints públicos funcionan sin API key."""
        response = fastapi_app_with_verifier.get("/public")
        assert response.status_code == 200
        assert response.json() == {"message": "Public endpoint"}
    
    @pytest.mark.unit
    def test_protected_endpoint_without_api_key(self, fastapi_app_with_verifier):
        """Test que los endpoints protegidos devuelven 401 sin API key."""
        response = fastapi_app_with_verifier.get("/protected")
        assert response.status_code == 401
        assert "API key required" in response.json()["detail"]
    
    @pytest.mark.unit
    def test_protected_endpoint_with_invalid_api_key(self, fastapi_app_with_verifier):
        """Test que una API key inválida devuelve 403."""
        response = fastapi_app_with_verifier.get(
            "/protected",
            headers={"X-Api-Key": "invalid-key"}
        )
        assert response.status_code == 403
        assert response.json()["detail"] == "Invalid API Key"
    
    @pytest.mark.unit
    def test_authentication_via_bearer_token(self, fastapi_app_with_verifier, api_key):
        """Test autenticación exitosa con Bearer token."""
        response = fastapi_app_with_verifier.get(
            "/protected",
            headers={"Authorization": f"Bearer {api_key}"}
        )
        assert response.status_code == 200
        assert response.json() == {"message": "Protected endpoint"}
    
    @pytest.mark.unit
    def test_authentication_via_x_api_key_header(self, fastapi_app_with_verifier, api_key):
        """Test autenticación exitosa con header X-Api-Key."""
        response = fastapi_app_with_verifier.get(
            "/protected",
            headers={"X-Api-Key": api_key}
        )
        assert response.status_code == 200
        assert response.json() == {"message": "Protected endpoint"}
    
    @pytest.mark.unit
    def test_authentication_via_query_parameter(self, fastapi_app_with_verifier, api_key):
        """Test autenticación exitosa con query parameter."""
        response = fastapi_app_with_verifier.get(f"/protected?api_key={api_key}")
        assert response.status_code == 200
        assert response.json() == {"message": "Protected endpoint"}
    
    @pytest.mark.unit
    def test_post_endpoint_with_authentication(self, fastapi_app_with_verifier, api_key):
        """Test endpoint POST con autenticación."""
        user_data = {"name": "John Doe", "email": "john@example.com"}
        response = fastapi_app_with_verifier.post(
            "/users",
            json=user_data,
            headers={"X-Api-Key": api_key}
        )
        assert response.status_code == 200
        assert response.json()["user_id"] == "123"
        assert response.json()["data"] == user_data
    
    @pytest.mark.unit
    def test_authentication_priority_bearer_over_x_api_key(self, fastapi_app_with_verifier, api_key):
        """Test que Bearer token tiene prioridad sobre X-Api-Key."""
        response = fastapi_app_with_verifier.get(
            "/protected",
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-Api-Key": "wrong-key"
            }
        )
        assert response.status_code == 200
    
    @pytest.mark.unit
    def test_authentication_priority_x_api_key_over_query(self, fastapi_app_with_verifier, api_key):
        """Test que X-Api-Key tiene prioridad sobre query parameter."""
        response = fastapi_app_with_verifier.get(
            "/protected?api_key=wrong-key",
            headers={"X-Api-Key": api_key}
        )
        assert response.status_code == 200
    
    @pytest.mark.unit
    def test_case_insensitive_x_api_key_header(self, fastapi_app_with_verifier, api_key):
        """Test que el header X-Api-Key es case-insensitive."""
        # FastAPI normaliza los headers a minúsculas internamente
        response = fastapi_app_with_verifier.get(
            "/protected",
            headers={"x-api-key": api_key}
        )
        assert response.status_code == 200
    
    @pytest.mark.integration
    def test_multiple_verifiers_with_different_keys(self):
        """Test usando múltiples verificadores con diferentes API keys."""
        admin_key = "admin-key-12345"
        user_key = "user-key-67890"
        
        app = FastAPI()
        verify_admin = create_api_key_verifier(admin_key)
        verify_user = create_api_key_verifier(user_key)
        
        @app.delete("/users/{user_id}")
        async def delete_user(
            user_id: str,
            admin_verified: None = Depends(verify_admin)
        ):
            return {"deleted": user_id}
        
        @app.get("/users")
        async def list_users(
            user_verified: None = Depends(verify_user)
        ):
            return {"users": ["user1", "user2"]}
        
        client = FastAPITestClient(app)
        
        # Admin endpoint con user key - debe fallar
        response = client.delete("/users/123", headers={"X-Api-Key": user_key})
        assert response.status_code == 403
        
        # Admin endpoint con admin key - debe funcionar
        response = client.delete("/users/123", headers={"X-Api-Key": admin_key})
        assert response.status_code == 200
        assert response.json() == {"deleted": "123"}
        
        # User endpoint con user key - debe funcionar
        response = client.get("/users", headers={"X-Api-Key": user_key})
        assert response.status_code == 200
        assert response.json() == {"users": ["user1", "user2"]}
    
    @pytest.mark.integration
    def test_verifier_with_router(self, api_key):
        """Test usando verificador con un router completo."""
        from fastapi import APIRouter
        
        app = FastAPI()
        verify_api_key = create_api_key_verifier(api_key)
        
        # Router protegido
        protected_router = APIRouter(dependencies=[Depends(verify_api_key)])
        
        @protected_router.get("/items")
        async def get_items():
            return {"items": ["item1", "item2"]}
        
        @protected_router.post("/items")
        async def create_item(item: dict):
            return {"created": item}
        
        app.include_router(protected_router, prefix="/api/v1")
        
        client = FastAPITestClient(app)
        
        # Sin API key - debe fallar
        response = client.get("/api/v1/items")
        assert response.status_code == 401
        
        # Con API key - debe funcionar
        response = client.get("/api/v1/items", headers={"X-Api-Key": api_key})
        assert response.status_code == 200
        assert response.json() == {"items": ["item1", "item2"]}
        
        # POST con API key
        item_data = {"name": "New Item", "price": 99.99}
        response = client.post(
            "/api/v1/items",
            json=item_data,
            headers={"X-Api-Key": api_key}
        )
        assert response.status_code == 200
        assert response.json() == {"created": item_data}