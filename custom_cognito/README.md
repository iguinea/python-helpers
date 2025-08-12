# FastAPI + AWS Cognito Authentication Starter

Implementación completa de autenticación con AWS Cognito usando FastAPI y pycognito. Este módulo proporciona endpoints listos para usar que incluyen registro, login, MFA, recuperación de contraseña y más.

## 1. INSTALACIÓN DE DEPENDENCIAS

### PIP

```bash
pip install fastapi uvicorn python-jose[cryptography] pycognito python-multipart
pip install redis pydantic-settings python-dotenv casbin
pip install pytest pytest-asyncio moto[cognitoidp] httpx
```

### UV

```bash
uv add fastapi uvicorn pycognito python-multipart redis pydantic-settings python-dotenv casbin pytest pytest-asyncio httpx python-jose moto
```

## 2. CONFIGURACIÓN

### Variables de Entorno

Copia el archivo `.env.example` a `.env` y configura tus credenciales de AWS Cognito:

```bash
cp .env.example .env
```

Variables requeridas:
- `AWS_REGION`: Región de AWS donde está tu User Pool
- `COGNITO_USER_POOL_ID`: ID del User Pool de Cognito
- `COGNITO_APP_CLIENT_ID`: ID del App Client
- `JWT_SECRET_KEY`: Clave secreta para JWT (genera una con `openssl rand -hex 32`)

### Configuración de AWS Cognito

1. Crea un User Pool en AWS Cognito con las siguientes características:
   - Atributos requeridos: email
   - Atributos opcionales: name, phone_number
   - Permitir auto-registro de usuarios
   - Verificación por email

2. Crea un App Client:
   - Sin secret (o con secret si lo prefieres)
   - Flujos de autenticación: ALLOW_USER_PASSWORD_AUTH, ALLOW_REFRESH_TOKEN_AUTH

## 3. USO

### Ejecutar la aplicación

```bash
# Modo desarrollo
uvicorn custom_cognito.main:app --reload --port 8000

# Modo producción
uvicorn custom_cognito.main:app --host 0.0.0.0 --port 8000
```

### Endpoints Disponibles

#### Autenticación

- `POST /api/auth/register` - Registrar nuevo usuario
- `POST /api/auth/verify-email` - Verificar email con código
- `POST /api/auth/login` - Iniciar sesión
- `POST /api/auth/logout` - Cerrar sesión
- `POST /api/auth/refresh` - Refrescar tokens
- `POST /api/auth/forgot-password` - Solicitar recuperación de contraseña
- `POST /api/auth/reset-password` - Confirmar nueva contraseña con código

#### MFA (Multi-Factor Authentication)

- `POST /api/auth/mfa/setup` - Configurar MFA
- `POST /api/auth/mfa/verify` - Verificar código MFA

#### Rutas Protegidas

- `GET /api/user/profile` - Obtener perfil del usuario autenticado

### Ejemplos de Uso

#### Registro de Usuario

```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "full_name": "John Doe",
    "phone_number": "+1234567890"
  }'
```

#### Login

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

#### Acceder a Ruta Protegida

```bash
curl -X GET http://localhost:8000/api/user/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 4. TESTS

### Tests con Mocks (por defecto)

```bash
# Todos los tests (excluye tests de integración real)
pytest

# Con cobertura
pytest --cov=custom_cognito

# Solo tests unitarios
pytest -m unit

# Tests específicos
pytest tests/test_schemas.py
```

### Tests de Integración Real

⚠️ **ADVERTENCIA**: Estos tests se conectan a AWS Cognito real y crearán usuarios de prueba.

```bash
# Ejecutar tests de integración real
pytest -m integration_real tests/

# Usando Make (incluye confirmación de seguridad)
make test-custom-cognito-real
```

Ver [README_INTEGRATION_TESTS.md](README_INTEGRATION_TESTS.md) para más detalles sobre los tests de integración.

## 5. ARQUITECTURA

### Estructura del Proyecto

```
custom_cognito/
├── __init__.py          # Exports públicos del módulo
├── main.py              # Endpoints de FastAPI
├── config.py            # Configuración con Pydantic Settings
├── schemas.py           # Modelos Pydantic para validación
├── cognito_service.py   # Lógica de negocio con AWS Cognito
├── auth.py              # Validación JWT y middleware de autenticación
├── .env.example         # Variables de entorno de ejemplo
├── pytest.ini           # Configuración de pytest
└── tests/               # Tests unitarios e integración
    ├── conftest.py      # Fixtures de pytest
    ├── test_schemas.py  # Tests de validación de datos
    ├── test_cognito_service.py  # Tests del servicio
    └── test_api_endpoints.py    # Tests de endpoints
```

### Flujo de Autenticación

1. **Registro**: El usuario se registra y recibe un código de verificación por email
2. **Verificación**: Confirma su email con el código recibido
3. **Login**: Inicia sesión con email y contraseña
4. **Tokens**: Recibe access_token (JWT) y refresh_token
5. **Autorización**: Usa el access_token en el header Authorization para acceder a rutas protegidas
6. **Refresh**: Cuando el access_token expira, usa el refresh_token para obtener nuevos tokens

## 6. SEGURIDAD

- Contraseñas con requisitos mínimos (mayúsculas, minúsculas, números, símbolos)
- Tokens JWT con expiración configurable
- Refresh tokens almacenados como cookies httpOnly
- Validación de tokens contra JWKS de Cognito
- CORS configurado para el dominio del frontend
- Rate limiting recomendado en producción

## 7. INTEGRACIÓN CON PYTHON-HELPERS

Este módulo puede integrarse al proyecto principal python-helpers como un módulo de autenticación reutilizable. Para usarlo en otros proyectos:

```python
from custom_cognito import CognitoService, get_current_user
from custom_cognito.schemas import UserRegister

# En tu aplicación FastAPI
from fastapi import Depends

@app.get("/protected")
async def protected_route(user = Depends(get_current_user)):
    return {"user": user}
```
