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
