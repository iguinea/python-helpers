# Custom Auth Module

## Descripción General

El módulo `custom_auth` proporciona middleware de autenticación por API key para aplicaciones web construidas con Starlette o FastAPI. Permite proteger endpoints de manera sencilla y flexible.

## Instalación

```python
from custom_auth.middleware import APIKeyAuthMiddleware, create_authentication_middleware
```

## Componentes Principales

### APIKeyAuthMiddleware

Middleware que intercepta todas las peticiones HTTP y verifica la presencia de una API key válida.

#### Constructor

```python
APIKeyAuthMiddleware(
    app,
    api_key: str,
    unauthenticated_paths: List[str] = []
)
```

**Parámetros:**
- `app`: Aplicación ASGI (Starlette/FastAPI)
- `api_key`: La API key válida que se debe proporcionar
- `unauthenticated_paths`: Lista de rutas que no requieren autenticación (ej: ["/health", "/ping"])

#### Métodos de Autenticación Soportados

1. **Authorization Header con Bearer Token**
   ```http
   Authorization: Bearer your-api-key-here
   ```

2. **X-API-Key Header**
   ```http
   X-API-Key: your-api-key-here
   ```

3. **Query Parameter**
   ```
   https://api.example.com/endpoint?api_key=your-api-key-here
   ```

### create_authentication_middleware

Función helper para crear middleware de autenticación de forma simplificada.

```python
def create_authentication_middleware(
    api_key: Optional[str] = None,
    unauthenticated_paths: Optional[List[str]] = ["/health", "/ping", "/status"]
) -> List[Middleware]
```

**Parámetros:**
- `api_key`: API key para autenticación. Si es None, la autenticación se deshabilita
- `unauthenticated_paths`: Rutas que no requieren autenticación

**Retorna:**
- Lista de middleware configurados o lista vacía si la autenticación está deshabilitada

### create_api_key_verifier

Función para crear un verificador de API key como dependencia de FastAPI. Ideal para proteger endpoints específicos en lugar de toda la aplicación.

```python
def create_api_key_verifier(api_key: str) -> Callable
```

**Parámetros:**
- `api_key`: La API key válida que se debe verificar

**Retorna:**
- Función verificadora para usar como dependencia de FastAPI con `Depends()`

**Métodos de autenticación soportados:**
- Authorization Bearer header
- X-API-Key header  
- Query parameter `api_key`

## Ejemplos de Uso

### Con Starlette

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from custom_auth.middleware import create_authentication_middleware

# Crear middleware con API key
middleware = create_authentication_middleware(
    api_key="my-secret-api-key",
    unauthenticated_paths=["/", "/health"]
)

# Definir rutas
async def homepage(request):
    return JSONResponse({"message": "Welcome to the API"})

async def protected(request):
    return JSONResponse({"data": "This is protected data"})

async def health(request):
    return JSONResponse({"status": "healthy"})

# Crear aplicación
app = Starlette(
    routes=[
        Route("/", homepage),
        Route("/protected", protected),
        Route("/health", health),
    ],
    middleware=middleware
)
```

### Con FastAPI - Middleware Global

```python
from fastapi import FastAPI
from custom_auth.middleware import APIKeyAuthMiddleware

app = FastAPI()

# Agregar middleware directamente
app.add_middleware(
    APIKeyAuthMiddleware,
    api_key="my-secret-api-key",
    unauthenticated_paths=["/health", "/docs", "/openapi.json"]
)

@app.get("/")
def read_root():
    return {"message": "Public endpoint"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.get("/protected")
def protected_endpoint():
    return {"data": "This requires authentication"}
```

### Con FastAPI - Endpoints Específicos

```python
from fastapi import FastAPI, Depends
from custom_auth.middleware import create_api_key_verifier

app = FastAPI()

# Crear verificador con tu API key
API_KEY = "my-secret-api-key"
verify_api_key = create_api_key_verifier(API_KEY)

# Endpoint público - no requiere autenticación
@app.get("/")
def read_root():
    return {"message": "Public endpoint"}

# Endpoint protegido - requiere API key
@app.get("/protected")
def protected_endpoint(api_key_verified: None = Depends(verify_api_key)):
    return {"data": "This requires authentication"}

# Proteger endpoint POST
@app.post("/users")
def create_user(
    user_data: dict,
    api_key_verified: None = Depends(verify_api_key)
):
    return {"user_id": "123", "data": user_data}
```

### Con FastAPI - Router Completo

```python
from fastapi import FastAPI, Depends, APIRouter
from custom_auth.middleware import create_api_key_verifier

app = FastAPI()
API_KEY = "my-secret-api-key"
verify_api_key = create_api_key_verifier(API_KEY)

# Router protegido - todos sus endpoints requieren API key
protected_router = APIRouter(dependencies=[Depends(verify_api_key)])

@protected_router.get("/items")
def get_items():
    return {"items": ["item1", "item2"]}

@protected_router.post("/items")
def create_item(item: dict):
    return {"created": item}

@protected_router.delete("/items/{item_id}")
def delete_item(item_id: str):
    return {"deleted": item_id}

# Incluir router con prefijo
app.include_router(protected_router, prefix="/api/v1")

# Endpoints públicos
@app.get("/")
def root():
    return {"message": "Public API"}
```

### Con FastAPI - Múltiples Niveles de Acceso

```python
from fastapi import FastAPI, Depends
from custom_auth.middleware import create_api_key_verifier

app = FastAPI()

# Diferentes API keys para diferentes niveles
ADMIN_KEY = "admin-secret-key"
USER_KEY = "user-secret-key"

verify_admin = create_api_key_verifier(ADMIN_KEY)
verify_user = create_api_key_verifier(USER_KEY)

# Endpoint solo para administradores
@app.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    admin_verified: None = Depends(verify_admin)
):
    return {"deleted": user_id}

# Endpoint para usuarios normales
@app.get("/users")
def list_users(
    user_verified: None = Depends(verify_user)
):
    return {"users": ["user1", "user2"]}

# Endpoint público
@app.get("/status")
def status():
    return {"status": "ok"}
```

### Configuración con Variables de Entorno

```python
import os
from custom_auth.middleware import create_authentication_middleware

# Leer API key de variable de entorno
api_key = os.environ.get("API_KEY")

middleware = create_authentication_middleware(
    api_key=api_key,
    unauthenticated_paths=["/health", "/metrics"]
)

if not api_key:
    print("⚠️ WARNING: API authentication is disabled!")
```

## Respuestas de Error

### Sin API Key (401 Unauthorized)

```json
{
    "error": "API key required",
    "message": "Please provide API key via Authorization header, X-API-Key header, or api_key query parameter"
}
```

### API Key Inválida (403 Forbidden)

```json
{
    "error": "Invalid API key",
    "message": "The provided API key is not valid"
}
```

## Mejores Prácticas

1. **Seguridad de API Keys**
   - Nunca hardcodees API keys en el código
   - Usa variables de entorno o gestores de secretos
   - Rota las API keys regularmente

2. **Rutas No Autenticadas**
   - Minimiza las rutas públicas
   - Incluye health checks y endpoints de monitoreo
   - En FastAPI, incluye `/docs` y `/openapi.json` si necesitas documentación pública

3. **Headers Case-Insensitive**
   - Los headers HTTP son case-insensitive
   - El middleware maneja automáticamente variaciones como `x-api-key`, `X-Api-Key`, etc.

4. **Prioridad de Autenticación**
   - Si se proporcionan múltiples métodos, la prioridad es:
     1. Authorization Bearer
     2. X-API-Key header
     3. Query parameter

## Testing

### Testing Middleware Global

```python
import pytest
from starlette.testclient import TestClient
from your_app import app

def test_protected_endpoint_without_key():
    client = TestClient(app)
    response = client.get("/protected")
    assert response.status_code == 401

def test_protected_endpoint_with_valid_key():
    client = TestClient(app)
    response = client.get(
        "/protected",
        headers={"X-API-Key": "valid-key"}
    )
    assert response.status_code == 200

def test_health_endpoint_without_key():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
```

### Testing Verificador de FastAPI

```python
import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI, Depends
from custom_auth.middleware import create_api_key_verifier

@pytest.fixture
def app_with_verifier():
    app = FastAPI()
    verify_api_key = create_api_key_verifier("test-key")
    
    @app.get("/public")
    def public():
        return {"message": "public"}
    
    @app.get("/protected")
    def protected(verified: None = Depends(verify_api_key)):
        return {"message": "protected"}
    
    return TestClient(app)

def test_public_endpoint(app_with_verifier):
    response = app_with_verifier.get("/public")
    assert response.status_code == 200

def test_protected_without_key(app_with_verifier):
    response = app_with_verifier.get("/protected")
    assert response.status_code == 401

def test_protected_with_bearer(app_with_verifier):
    response = app_with_verifier.get(
        "/protected",
        headers={"Authorization": "Bearer test-key"}
    )
    assert response.status_code == 200

def test_protected_with_x_api_key(app_with_verifier):
    response = app_with_verifier.get(
        "/protected",
        headers={"X-Api-Key": "test-key"}
    )
    assert response.status_code == 200

def test_protected_with_query(app_with_verifier):
    response = app_with_verifier.get("/protected?api_key=test-key")
    assert response.status_code == 200
```

## Troubleshooting

### El middleware no se está aplicando
- Verifica que el middleware esté agregado antes de las rutas
- En FastAPI, usa `app.add_middleware()` después de crear la app

### Headers no reconocidos
- Asegúrate de que no haya espacios extra en el header
- Verifica que el formato Bearer tenga exactamente un espacio: `Bearer token`

### Rutas públicas requieren autenticación
- Verifica que las rutas en `unauthenticated_paths` coincidan exactamente
- Las rutas deben incluir el path completo (ej: `/api/v1/health` no `/health`)