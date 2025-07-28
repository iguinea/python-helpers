from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from typing import Callable, Awaitable, Optional, List
from starlette.middleware import Middleware


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware para autenticación por API key en el servidor MCP.

    La API key debe proporcionarse en uno de estos formatos:
    1. Header: Authorization: Bearer <api_key>
    2. Header: X-API-Key: <api_key>
    3. Query parameter: ?api_key=<api_key>
    """

    def __init__(self, app, api_key: str, unauthenticated_paths: List[str] = []):
        super().__init__(app)
        self.unauthenticated_paths = unauthenticated_paths
        self.api_key = api_key
        if not self.api_key:
            raise ValueError("API key must be provided")

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable]
    ):
        # Permitir requests de health check sin autenticación
        if request.url.path in self.unauthenticated_paths:
            return await call_next(request)

        # Extraer API key del request
        api_key = self._extract_api_key(request)

        if not api_key:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "API key required",
                    "message": "Please provide API key via Authorization header, X-API-Key header, or api_key query parameter",
                },
            )

        if api_key != self.api_key:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Invalid API key",
                    "message": "The provided API key is not valid",
                },
            )

        # API key válida, continuar con el request
        return await call_next(request)

    def _extract_api_key(self, request: Request) -> str:
        """Extrae la API key de diferentes fuentes del request."""

        # 1. Authorization header con Bearer token
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]  # Remove "Bearer " prefix

        # 2. X-API-Key header
        api_key_header = request.headers.get("x-api-key", "")
        if api_key_header:
            return api_key_header

        # 3. Query parameter
        api_key_param = request.query_params.get("api_key", "")
        if api_key_param:
            return api_key_param

        return ""


def create_authentication_middleware(
    api_key: Optional[str] = None,
    unauthenticated_paths: Optional[List[str]] = ["/health", "/ping", "/status"],
) -> List[Middleware]:
    """
    Create authentication middleware with the provided API key.

    Args:
        api_key: The API key to use for authentication. If None, authentication is disabled.

    Returns:
        List of middleware to apply, or empty list if authentication is disabled.
    """
    middleware = []

    if api_key:
        try:
            auth_middleware = Middleware(
                APIKeyAuthMiddleware,
                api_key=api_key,
                unauthenticated_paths=unauthenticated_paths,
            )
            middleware.append(auth_middleware)
            print("✅ API key authentication enabled")
            print("  Supported formats:")
            print("    - Header: Authorization: Bearer <api_key>")
            print("    - Header: X-API-Key: <api_key>")
            print("    - Query param: ?api_key=<api_key>")

        except ValueError as e:
            print(f"ERROR: Authentication configuration error: {e}")
            return None
    else:
        print("⚠️ Authentication disabled - server will accept requests without API key")

    return middleware


# This function is no longer needed - API key comes from unified config
# load_api_key_from_secrets_manager has been removed
# The API key is now loaded from the unified MCP_SECRETS secret
# and passed directly to the middleware during initialization


def create_api_key_verifier(api_key: str):
    """
    Crea una función verificadora de API key para usar con FastAPI.
    
    Esta función retorna una dependencia de FastAPI que puede ser usada
    para verificar la API key en endpoints específicos. Soporta tres métodos
    de autenticación:
    
    1. Header Authorization con Bearer token
    2. Header X-API-Key
    3. Query parameter api_key
    
    Args:
        api_key: La API key válida para comparar
        
    Returns:
        Función verificadora para usar como dependencia de FastAPI
        
    Examples:
        
        Configuración básica:
        ```python
        from fastapi import FastAPI, Depends
        from custom_auth.middleware import create_api_key_verifier
        
        app = FastAPI()
        API_KEY = get_api_key()  # Obtener API key de tu fuente
        verify_api_key = create_api_key_verifier(API_KEY)
        ```
        
        Uso en endpoints individuales:
        ```python
        @app.get("/protected")
        async def protected_endpoint(api_key_verified: None = Depends(verify_api_key)):
            return {"message": "Access granted"}
        
        @app.post("/users")
        async def create_user(
            user_data: dict,
            api_key_verified: None = Depends(verify_api_key)
        ):
            return {"user_id": "123", "data": user_data}
        ```
        
        Uso en un router completo:
        ```python
        from fastapi import APIRouter
        
        # Proteger todos los endpoints de un router
        protected_router = APIRouter(dependencies=[Depends(verify_api_key)])
        
        @protected_router.get("/items")
        async def get_items():
            return {"items": ["item1", "item2"]}
        
        @protected_router.post("/items")
        async def create_item(item: dict):
            return {"created": item}
        
        app.include_router(protected_router, prefix="/api/v1")
        ```
        
        Uso con múltiples API keys (diferentes niveles de acceso):
        ```python
        # API keys para diferentes niveles
        ADMIN_KEY = get_api_key("admin")
        USER_KEY = get_api_key("user")
        
        verify_admin = create_api_key_verifier(ADMIN_KEY)
        verify_user = create_api_key_verifier(USER_KEY)
        
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
        ```
        
        Ejemplos de requests válidos:
        
        1. Usando Authorization Bearer:
        ```bash
        curl -H "Authorization: Bearer tu-api-key-secreta" http://localhost:8000/protected
        ```
        
        2. Usando X-API-Key header:
        ```bash
        curl -H "X-Api-Key: tu-api-key-secreta" http://localhost:8000/protected
        ```
        
        3. Usando query parameter:
        ```bash
        curl "http://localhost:8000/protected?api_key=tu-api-key-secreta"
        ```
        
        Respuestas de error:
        
        - 401 Unauthorized: Cuando no se proporciona API key
        - 403 Forbidden: Cuando la API key es inválida
    """
    from fastapi import Header, HTTPException, Query
    
    async def verify_api_key(
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
        api_key_param: Optional[str] = Query(None, alias="api_key")
    ):
        """Verifica la API key del request."""
        # Extraer API key de diferentes fuentes
        extracted_key = None
        
        # 1. Authorization header con Bearer token
        if authorization and authorization.startswith("Bearer "):
            extracted_key = authorization[7:]
        
        # 2. X-API-Key header
        elif x_api_key:
            extracted_key = x_api_key
            
        # 3. Query parameter
        elif api_key_param:
            extracted_key = api_key_param
            
        # Verificar si se proporcionó API key
        if not extracted_key:
            raise HTTPException(
                status_code=401,
                detail="API key required. Provide via Authorization: Bearer <key>, X-Api-Key: <key>, or ?api_key=<key>"
            )
        
        # Verificar si la API key es válida
        if extracted_key != api_key:
            raise HTTPException(
                status_code=403,
                detail="Invalid API Key"
            )
    
    return verify_api_key
