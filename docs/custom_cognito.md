# Custom Cognito

El módulo `custom_cognito` proporciona una implementación completa de autenticación usando AWS Cognito con FastAPI. Incluye registro de usuarios, verificación de email, login, MFA, recuperación de contraseña y validación JWT.

## Notas Importantes de Implementación

### Autenticación con pycognito

Este módulo utiliza la biblioteca `pycognito` para la autenticación. Es importante tener en cuenta:

1. **El método `authenticate()` no retorna valores**: Los tokens se almacenan como atributos del objeto Cognito después de una autenticación exitosa.
   
2. **Acceso a tokens**: Después de `cognito_user.authenticate()`, los tokens están disponibles como:
   - `cognito_user.access_token`
   - `cognito_user.refresh_token`
   - `cognito_user.id_token`
   - `cognito_user.expires_in` (puede no estar disponible en todas las versiones)

3. **Manejo de usernames**: Cuando se usa email como alias, Cognito genera un username único. El servicio maneja esto automáticamente usando `_get_username_by_email()` antes de autenticar.

## Instalación

```python
from custom_cognito import CognitoService, get_current_user
from custom_cognito.schemas import UserRegister, UserLogin
from custom_cognito.config import Settings
```

## Configuración

### Variables de Entorno Requeridas

```bash
# AWS Cognito
AWS_REGION=us-east-1
AWS_PROFILE=your-profile  # Opcional, para usar perfil AWS específico
COGNITO_USER_POOL_ID=your-user-pool-id
COGNITO_APP_CLIENT_ID=your-app-client-id
COGNITO_APP_CLIENT_SECRET=  # Opcional, solo si el App Client tiene secret

# Aplicación
FRONTEND_URL=http://localhost:3000
REDIS_URL=redis://localhost:6379/0
JWT_SECRET_KEY=your-secret-key
ENVIRONMENT=development

# Tokens
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=30
```

### Configuración de Credenciales AWS

El módulo soporta múltiples formas de configurar las credenciales AWS:

1. **Perfil AWS** (recomendado para desarrollo):
   ```bash
   AWS_PROFILE=your-profile
   ```

2. **Credenciales directas** (para entornos CI/CD):
   ```bash
   AWS_ACCESS_KEY_ID=your-access-key
   AWS_SECRET_ACCESS_KEY=your-secret-key
   ```

3. **Credenciales por defecto**: Si no se especifica ninguna, usa las credenciales por defecto del entorno

### Configuración de AWS Cognito

1. **Crear User Pool**:
   - Atributos requeridos: `email`
   - Atributos opcionales: `name`, `phone_number`
   - Habilitar auto-registro
   - Verificación por email

2. **Crear App Client**:
   - Flujos de autenticación: `ALLOW_USER_PASSWORD_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH`
   - Con o sin secret (ajustar configuración según corresponda)

## Uso Básico

### 1. Configurar FastAPI con Autenticación

```python
from fastapi import FastAPI, Depends
from custom_cognito import get_current_user
from custom_cognito.main import app as cognito_app

# Opción 1: Usar la app completa
app = cognito_app

# Opción 2: Integrar en tu propia app
app = FastAPI()

# Montar las rutas de autenticación
app.mount("/auth", cognito_app)

# Crear rutas protegidas
@app.get("/protected")
async def protected_route(user = Depends(get_current_user)):
    return {"message": f"Hola {user['email']}"}
```

### 2. Servicio Cognito Standalone

```python
from custom_cognito import CognitoService, settings
from custom_cognito.schemas import UserRegister

# Inicializar servicio
cognito = CognitoService(settings)

# Registrar usuario
user_data = UserRegister(
    email="user@example.com",
    password="SecurePass123!",
    full_name="Juan Pérez",
    phone_number="+34600123456"
)

result = await cognito.register_user(user_data)
print(f"Usuario registrado: {result['user_sub']}")

# Login
tokens = await cognito.login("user@example.com", "SecurePass123!")
access_token = tokens['access_token']
```

### 3. Validación JWT Personalizada

```python
from custom_cognito.auth import JWTValidator, settings

# Crear validador
validator = JWTValidator(settings)

# Validar token
try:
    payload = await validator.validate_token(access_token)
    print(f"Usuario autenticado: {payload['email']}")
except HTTPException as e:
    print(f"Token inválido: {e.detail}")
```

## Endpoints de API

### Autenticación

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/api/auth/register` | Registrar nuevo usuario |
| POST | `/api/auth/verify-email` | Verificar email con código |
| POST | `/api/auth/login` | Iniciar sesión |
| POST | `/api/auth/logout` | Cerrar sesión |
| POST | `/api/auth/refresh` | Refrescar tokens |
| POST | `/api/auth/forgot-password` | Solicitar recuperación de contraseña |
| POST | `/api/auth/reset-password` | Confirmar nueva contraseña |

### MFA

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| POST | `/api/auth/mfa/setup` | Configurar MFA |
| POST | `/api/auth/mfa/verify` | Verificar código MFA |

### Rutas Protegidas

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/api/user/profile` | Obtener perfil del usuario |

## Ejemplos de Requests

### Registro

```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "full_name": "Juan Pérez",
    "phone_number": "+34600123456"
  }'
```

Respuesta:
```json
{
  "message": "Registration successful. Please check your email for verification code.",
  "data": {
    "user_sub": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "confirmation_required": true
  }
}
```

### Login

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

Respuesta:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "id_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Acceder a Ruta Protegida

```bash
curl -X GET http://localhost:8000/api/user/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Schemas de Validación

### UserRegister

```python
class UserRegister(BaseModel):
    email: EmailStr
    password: str  # Min 8 chars, debe incluir mayúsculas, minúsculas, números y símbolos
    full_name: str
    phone_number: Optional[str] = None
```

### UserLogin

```python
class UserLogin(BaseModel):
    email: EmailStr
    password: str
```

### TokenResponse

```python
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    id_token: str
    token_type: str = "Bearer"
    expires_in: int
```

## Manejo de Errores

El módulo maneja los siguientes tipos de errores:

### Errores de Validación (422)
```json
{
  "detail": [
    {
      "loc": ["body", "password"],
      "msg": "Password must contain at least one uppercase letter",
      "type": "value_error"
    }
  ]
}
```

### Errores de Autenticación (401)
```json
{
  "detail": "Invalid email or password"
}
```

### Errores de Negocio (400)
```json
{
  "detail": "User with this email already exists"
}
```

## Seguridad

### Validación de Contraseñas

Las contraseñas deben cumplir:
- Mínimo 8 caracteres
- Al menos una mayúscula
- Al menos una minúscula
- Al menos un número
- Al menos un símbolo especial

### Tokens JWT

- **Access Token**: Válido por 60 minutos (configurable)
- **Refresh Token**: Válido por 30 días (configurable)
- Validación contra JWKS de AWS Cognito
- Verificación de issuer y audience

### Cookies

- Refresh token almacenado como cookie `httpOnly`
- Flag `secure` habilitado en producción
- `SameSite=lax` para prevenir CSRF

## Testing

### Tests con Mocks

```python
import pytest
from custom_cognito.tests.conftest import test_app, test_user_data

def test_register_user(test_app, test_user_data):
    response = test_app.post("/api/auth/register", json=test_user_data)
    assert response.status_code == 200
    assert "user_sub" in response.json()["data"]
```

### Tests de Integración Real

El módulo incluye tests de integración que se conectan a AWS Cognito real:

```bash
# Ejecutar tests de integración real
cd custom_cognito
pytest -m integration_real tests/

# O usando Make desde el directorio principal
make test-custom-cognito-real
```

⚠️ **Advertencia**: Los tests de integración real crearán usuarios en tu User Pool. Úsalos solo con un User Pool de desarrollo.

Los tests incluyen limpieza automática de usuarios creados durante las pruebas.

### Utilidades de Prueba

Se incluyen scripts útiles para pruebas manuales en el directorio `tools/cognito/`:

```bash
# Usando Make (recomendado)
make cognito-list-users       # Listar todos los usuarios
make cognito-disable-users    # Desactivar todos los usuarios
make cognito-delete-users     # Eliminar todos los usuarios
make cognito-test-interactive # Test interactivo de registro
make cognito-test-demo        # Demo de registro

# Ejecutando directamente
python tools/cognito/list_cognito_users.py
python tools/cognito/disable_cognito_users.py
python tools/cognito/delete_cognito_users.py
python tools/cognito/test_cognito_user_interactive.py
python tools/cognito/test_cognito_user_demo.py
```

**Nota**: Todos los scripts requieren configuración en `/workspace_python-helpers/custom_cognito/.env`

## Integración con Redis (Opcional)

Para manejo de sesiones con Redis:

```python
import redis
from custom_cognito.config import settings

redis_client = redis.from_url(settings.redis_url)

# Guardar sesión después del login
def save_session(user_id: str, tokens: dict):
    redis_client.setex(
        f"session:{user_id}",
        settings.access_token_expire_minutes * 60,
        json.dumps(tokens)
    )

# Invalidar sesión en logout
def invalidate_session(user_id: str):
    redis_client.delete(f"session:{user_id}")
```

## Troubleshooting

### Error: "Public key not found"
- Verifica que el `COGNITO_USER_POOL_ID` sea correcto
- Asegúrate de que la región AWS sea la correcta

### Error: "Invalid token"
- Verifica que el token no haya expirado
- Confirma que el `COGNITO_APP_CLIENT_ID` sea correcto

### Error: "User pool does not exist"
- Verifica las credenciales AWS
- Confirma que el User Pool existe en la región especificada