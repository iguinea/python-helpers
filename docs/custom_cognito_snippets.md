# Custom Cognito - Guía de Código y Snippets

Esta guía proporciona ejemplos prácticos de código para usar todas las funciones del módulo `custom_cognito`.

## Tabla de Contenidos

1. [Configuración Inicial](#configuración-inicial)
2. [Registro de Usuario](#registro-de-usuario)
3. [Confirmación de Email](#confirmación-de-email)
4. [Login](#login)
5. [Gestión de Contraseñas](#gestión-de-contraseñas)
6. [Tokens y Refresh](#tokens-y-refresh)
7. [Autenticación Multifactor (MFA)](#autenticación-multifactor-mfa)
8. [Logout](#logout)
9. [Proteger Endpoints con JWT](#proteger-endpoints-con-jwt)
10. [Flujos Completos](#flujos-completos)
11. [Manejo de Errores](#manejo-de-errores)

## Configuración Inicial

### Importaciones Necesarias

```python
import asyncio
from typing import Dict, Any, Optional
from custom_cognito import CognitoService
from custom_cognito.config import Settings
from custom_cognito.schemas import UserRegister, UserLogin, PasswordReset
from custom_cognito.auth import get_current_user
from fastapi import FastAPI, Depends, HTTPException, status
```

### Configurar el Servicio

```python
# Crear configuración desde variables de entorno
settings = Settings()

# Inicializar el servicio de Cognito
cognito_service = CognitoService(settings)

# Para FastAPI
app = FastAPI()
```

### Variables de Entorno Requeridas (.env)

```bash
AWS_REGION=eu-west-1
AWS_PROFILE=your-profile  # Opcional
COGNITO_USER_POOL_ID=eu-west-1_xxxxx
COGNITO_APP_CLIENT_ID=xxxxxxxxxxxxx
COGNITO_APP_CLIENT_SECRET=xxxxx  # Solo si el App Client tiene secret
JWT_SECRET_KEY=your-secret-key
FRONTEND_URL=http://localhost:3000
REDIS_URL=redis://localhost:6379/0  # Opcional
```

## Registro de Usuario

### Registro Básico

```python
async def register_user_example():
    """Ejemplo de registro de usuario"""
    
    # Crear datos del usuario
    user_data = UserRegister(
        email="usuario@ejemplo.com",
        password="ContraseñaSegura123!",
        full_name="Juan Pérez",
        phone_number="+34600123456"  # Opcional
    )
    
    try:
        # Registrar usuario
        result = await cognito_service.register_user(user_data)
        
        print(f"Usuario registrado exitosamente!")
        print(f"User Sub: {result['user_sub']}")
        print(f"Username: {result['username']}")
        print(f"Email: {result['email']}")
        print(f"Confirmación requerida: {result['confirmation_required']}")
        
        return result
        
    except ValueError as e:
        print(f"Error de validación: {e}")
    except Exception as e:
        print(f"Error al registrar: {e}")
```

### Endpoint FastAPI para Registro

```python
@app.post("/api/auth/register")
async def register_endpoint(user_data: UserRegister):
    """Endpoint para registrar nuevos usuarios"""
    try:
        result = await cognito_service.register_user(user_data)
        return {
            "status": "success",
            "message": "Usuario registrado. Por favor, confirma tu email.",
            "data": result
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
```

## Confirmación de Email

### Confirmar Email con Código

```python
async def confirm_email_example():
    """Ejemplo de confirmación de email"""
    
    email = "usuario@ejemplo.com"
    codigo = "123456"  # Código recibido por email
    
    try:
        # Confirmar email
        confirmado = await cognito_service.confirm_email(email, codigo)
        
        if confirmado:
            print("Email confirmado exitosamente!")
            return True
            
    except ValueError as e:
        print(f"Error: {e}")
        if "Invalid verification code" in str(e):
            print("Código inválido")
        elif "Verification code has expired" in str(e):
            print("Código expirado")
```

### Endpoint FastAPI para Confirmación

```python
from pydantic import BaseModel, EmailStr

class EmailConfirmation(BaseModel):
    email: EmailStr
    code: str

@app.post("/api/auth/confirm-email")
async def confirm_email_endpoint(data: EmailConfirmation):
    """Endpoint para confirmar email"""
    try:
        await cognito_service.confirm_email(data.email, data.code)
        return {
            "status": "success",
            "message": "Email confirmado exitosamente"
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
```

## Login

### Login Básico

```python
async def login_example():
    """Ejemplo de login"""
    
    email = "usuario@ejemplo.com"
    password = "ContraseñaSegura123!"
    
    try:
        # Hacer login
        tokens = await cognito_service.login(email, password)
        
        print("Login exitoso!")
        print(f"Access Token: {tokens['access_token'][:50]}...")
        print(f"Refresh Token: {tokens['refresh_token'][:50]}...")
        print(f"ID Token: {tokens['id_token'][:50]}...")
        print(f"Expira en: {tokens['expires_in']} segundos")
        
        return tokens
        
    except ValueError as e:
        print(f"Error de login: {e}")
        if "Email not verified" in str(e):
            print("El email no está verificado")
        elif "Invalid email or password" in str(e):
            print("Email o contraseña incorrectos")
```

### Endpoint FastAPI para Login con Cookie

```python
from fastapi import Response

@app.post("/api/auth/login")
async def login_endpoint(
    user_data: UserLogin,
    response: Response
):
    """Endpoint para login con cookie de refresh token"""
    try:
        # Hacer login
        tokens = await cognito_service.login(
            user_data.email,
            user_data.password
        )
        
        # Guardar refresh token en cookie httpOnly
        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh_token"],
            httponly=True,
            secure=settings.environment == "production",
            samesite="lax",
            max_age=30 * 24 * 60 * 60  # 30 días
        )
        
        # Retornar solo access token e id token
        return {
            "status": "success",
            "data": {
                "access_token": tokens["access_token"],
                "id_token": tokens["id_token"],
                "expires_in": tokens["expires_in"]
            }
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
```

## Gestión de Contraseñas

### Iniciar Recuperación de Contraseña

```python
async def forgot_password_example():
    """Ejemplo de recuperación de contraseña"""
    
    email = "usuario@ejemplo.com"
    
    try:
        # Enviar código de recuperación
        enviado = await cognito_service.initiate_password_reset(email)
        
        if enviado:
            print(f"Código de recuperación enviado a {email}")
            return True
            
    except Exception as e:
        print(f"Error: {e}")
```

### Confirmar Nueva Contraseña

```python
async def reset_password_example():
    """Ejemplo de confirmar nueva contraseña"""
    
    email = "usuario@ejemplo.com"
    codigo = "123456"  # Código recibido por email
    nueva_password = "NuevaContraseña123!"
    
    try:
        # Confirmar nueva contraseña
        confirmado = await cognito_service.confirm_password_reset(
            email, 
            codigo, 
            nueva_password
        )
        
        if confirmado:
            print("Contraseña actualizada exitosamente!")
            return True
            
    except ValueError as e:
        print(f"Error: {e}")
```

### Endpoints FastAPI para Gestión de Contraseñas

```python
class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    email: EmailStr
    code: str
    new_password: str

@app.post("/api/auth/forgot-password")
async def forgot_password_endpoint(data: ForgotPassword):
    """Endpoint para solicitar recuperación de contraseña"""
    try:
        await cognito_service.initiate_password_reset(data.email)
        return {
            "status": "success",
            "message": "Si el email existe, recibirás un código de recuperación"
        }
    except Exception as e:
        # No revelar si el usuario existe
        return {
            "status": "success",
            "message": "Si el email existe, recibirás un código de recuperación"
        }

@app.post("/api/auth/reset-password")
async def reset_password_endpoint(data: ResetPassword):
    """Endpoint para confirmar nueva contraseña"""
    try:
        await cognito_service.confirm_password_reset(
            data.email,
            data.code,
            data.new_password
        )
        return {
            "status": "success",
            "message": "Contraseña actualizada exitosamente"
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
```

## Tokens y Refresh

### Renovar Tokens con Refresh Token

```python
async def refresh_tokens_example():
    """Ejemplo de renovar tokens"""
    
    refresh_token = "eyJjdHkiOiJKV1QiLCJlbmMiOi..."  # Token de refresh guardado
    
    try:
        # Renovar tokens
        new_tokens = await cognito_service.refresh_tokens(refresh_token)
        
        print("Tokens renovados!")
        print(f"Nuevo Access Token: {new_tokens['access_token'][:50]}...")
        print(f"Nuevo ID Token: {new_tokens['id_token'][:50]}...")
        print(f"Expira en: {new_tokens['expires_in']} segundos")
        
        return new_tokens
        
    except Exception as e:
        print(f"Error al renovar tokens: {e}")
```

### Endpoint FastAPI para Refresh con Cookie

```python
from fastapi import Request

@app.post("/api/auth/refresh")
async def refresh_endpoint(request: Request):
    """Endpoint para renovar tokens usando cookie"""
    # Obtener refresh token de la cookie
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token found"
        )
    
    try:
        # Renovar tokens
        new_tokens = await cognito_service.refresh_tokens(refresh_token)
        
        return {
            "status": "success",
            "data": {
                "access_token": new_tokens["access_token"],
                "id_token": new_tokens["id_token"],
                "expires_in": new_tokens["expires_in"]
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
```

## Autenticación Multifactor (MFA)

### Configurar MFA

```python
async def setup_mfa_example():
    """Ejemplo de configurar MFA"""
    
    access_token = "eyJraWQiOiI..."  # Token de acceso del usuario
    
    try:
        # Configurar MFA
        mfa_setup = await cognito_service.setup_mfa(access_token)
        
        print("Configuración MFA:")
        print(f"Código secreto: {mfa_setup['secret_code']}")
        print(f"URL QR: {mfa_setup['qr_code_url']}")
        
        # El usuario debe escanear el QR o ingresar el código en su app
        return mfa_setup
        
    except Exception as e:
        print(f"Error al configurar MFA: {e}")
```

### Verificar y Habilitar MFA

```python
async def verify_mfa_example():
    """Ejemplo de verificar MFA"""
    
    access_token = "eyJraWQiOiI..."  # Token de acceso
    codigo_mfa = "123456"  # Código de la app autenticadora
    
    try:
        # Verificar y habilitar MFA
        verificado = await cognito_service.verify_mfa_setup(
            access_token, 
            codigo_mfa
        )
        
        if verificado:
            print("MFA habilitado exitosamente!")
            return True
            
    except ValueError as e:
        print(f"Error: {e}")
```

## Logout

### Logout Global

```python
async def logout_example():
    """Ejemplo de logout"""
    
    access_token = "eyJraWQiOiI..."  # Token de acceso del usuario
    
    try:
        # Hacer logout global (revoca todos los tokens)
        logout_exitoso = await cognito_service.logout(access_token)
        
        if logout_exitoso:
            print("Logout exitoso!")
            return True
            
    except Exception as e:
        print(f"Error al hacer logout: {e}")
```

### Endpoint FastAPI para Logout

```python
@app.post("/api/auth/logout")
async def logout_endpoint(
    response: Response,
    current_user: dict = Depends(get_current_user)
):
    """Endpoint para logout"""
    try:
        # Hacer logout en Cognito
        await cognito_service.logout(current_user["access_token"])
        
        # Eliminar cookie de refresh token
        response.delete_cookie("refresh_token")
        
        return {
            "status": "success",
            "message": "Logout exitoso"
        }
        
    except Exception as e:
        # Aunque falle, eliminar la cookie
        response.delete_cookie("refresh_token")
        return {
            "status": "success",
            "message": "Logout exitoso"
        }
```

## Proteger Endpoints con JWT

### Dependency para Obtener Usuario Actual

```python
from custom_cognito.auth import get_current_user

# Uso básico
@app.get("/api/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Obtener información del usuario actual"""
    return {
        "email": current_user["email"],
        "sub": current_user["sub"],
        "name": current_user.get("name", ""),
        "email_verified": current_user.get("email_verified", False)
    }
```

### Proteger Endpoints con Roles (Opcional)

```python
from functools import wraps
from typing import List

def require_roles(allowed_roles: List[str]):
    """Decorator para requerir roles específicos"""
    def decorator(func):
        @wraps(func)
        async def wrapper(
            current_user: dict = Depends(get_current_user),
            *args, 
            **kwargs
        ):
            # Verificar roles del usuario
            user_roles = current_user.get("cognito:groups", [])
            
            if not any(role in user_roles for role in allowed_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="No tienes permisos para acceder a este recurso"
                )
            
            return await func(current_user=current_user, *args, **kwargs)
        return wrapper
    return decorator

# Uso
@app.get("/api/admin/users")
@require_roles(["admin", "superadmin"])
async def get_all_users(current_user: dict = Depends(get_current_user)):
    """Endpoint solo para administradores"""
    return {"message": "Lista de usuarios"}
```

## Flujos Completos

### Flujo Completo de Registro y Login

```python
async def complete_auth_flow():
    """Flujo completo de autenticación"""
    
    # 1. Registrar usuario
    user_data = UserRegister(
        email="nuevo@ejemplo.com",
        password="Password123!",
        full_name="Nuevo Usuario"
    )
    
    try:
        print("1. Registrando usuario...")
        registro = await cognito_service.register_user(user_data)
        print(f"   ✓ Usuario registrado: {registro['username']}")
        
        # 2. Simular confirmación de email
        print("\n2. Esperando confirmación de email...")
        codigo = input("   Ingresa el código recibido por email: ")
        
        # 3. Confirmar email
        print("\n3. Confirmando email...")
        await cognito_service.confirm_email(user_data.email, codigo)
        print("   ✓ Email confirmado")
        
        # 4. Hacer login
        print("\n4. Haciendo login...")
        tokens = await cognito_service.login(
            user_data.email, 
            user_data.password
        )
        print("   ✓ Login exitoso")
        print(f"   Access Token: {tokens['access_token'][:50]}...")
        
        return tokens
        
    except Exception as e:
        print(f"Error en el flujo: {e}")
        return None
```

### Flujo con Manejo de Sesión

```python
import redis
import json
from datetime import timedelta

class SessionManager:
    """Gestor de sesiones con Redis"""
    
    def __init__(self, redis_url: str):
        self.redis_client = redis.from_url(redis_url)
    
    async def create_session(
        self, 
        user_id: str, 
        tokens: Dict[str, Any],
        ttl: int = 3600
    ) -> str:
        """Crear sesión en Redis"""
        session_id = str(uuid.uuid4())
        
        session_data = {
            "user_id": user_id,
            "access_token": tokens["access_token"],
            "id_token": tokens["id_token"],
            "expires_at": time.time() + tokens["expires_in"]
        }
        
        # Guardar en Redis
        self.redis_client.setex(
            f"session:{session_id}",
            ttl,
            json.dumps(session_data)
        )
        
        return session_id
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Obtener sesión de Redis"""
        data = self.redis_client.get(f"session:{session_id}")
        
        if data:
            return json.loads(data)
        return None
    
    async def delete_session(self, session_id: str):
        """Eliminar sesión"""
        self.redis_client.delete(f"session:{session_id}")

# Uso con FastAPI
session_manager = SessionManager(settings.redis_url)

@app.post("/api/auth/login-with-session")
async def login_with_session(
    user_data: UserLogin,
    response: Response
):
    """Login que crea sesión en Redis"""
    try:
        # Hacer login
        tokens = await cognito_service.login(
            user_data.email,
            user_data.password
        )
        
        # Decodificar ID token para obtener user_id
        import jwt
        id_claims = jwt.decode(
            tokens["id_token"], 
            options={"verify_signature": False}
        )
        
        # Crear sesión
        session_id = await session_manager.create_session(
            user_id=id_claims["sub"],
            tokens=tokens,
            ttl=tokens["expires_in"]
        )
        
        # Guardar session_id en cookie
        response.set_cookie(
            key="session_id",
            value=session_id,
            httponly=True,
            secure=settings.environment == "production",
            samesite="lax"
        )
        
        return {
            "status": "success",
            "message": "Login exitoso"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
```

## Manejo de Errores

### Manejo Completo de Errores

```python
from custom_cognito.exceptions import (
    UserNotConfirmedException,
    InvalidPasswordException,
    UserNotFoundException
)

async def login_with_error_handling():
    """Ejemplo de login con manejo completo de errores"""
    
    try:
        tokens = await cognito_service.login(email, password)
        return {"status": "success", "tokens": tokens}
        
    except ValueError as e:
        error_msg = str(e)
        
        if "Email not verified" in error_msg:
            return {
                "status": "error",
                "error_code": "EMAIL_NOT_VERIFIED",
                "message": "Por favor, confirma tu email antes de iniciar sesión"
            }
            
        elif "Invalid email or password" in error_msg:
            return {
                "status": "error",
                "error_code": "INVALID_CREDENTIALS",
                "message": "Email o contraseña incorrectos"
            }
            
        elif "Password change required" in error_msg:
            return {
                "status": "error",
                "error_code": "PASSWORD_CHANGE_REQUIRED",
                "message": "Debes cambiar tu contraseña temporal"
            }
            
        else:
            return {
                "status": "error",
                "error_code": "AUTH_ERROR",
                "message": error_msg
            }
            
    except Exception as e:
        # Log del error
        print(f"Error inesperado en login: {e}")
        
        return {
            "status": "error",
            "error_code": "INTERNAL_ERROR",
            "message": "Error interno del servidor"
        }
```

### Middleware Global de Errores para FastAPI

```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Manejador global de excepciones HTTP"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "message": exc.detail,
            "path": str(request.url)
        }
    )

@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Manejador de errores de validación"""
    return JSONResponse(
        status_code=400,
        content={
            "status": "error",
            "message": str(exc),
            "type": "validation_error"
        }
    )
```

## Ejemplos de Uso Avanzado

### Integración con Base de Datos

```python
from sqlalchemy.orm import Session
from datetime import datetime

async def register_with_db_sync(
    user_data: UserRegister,
    db: Session
):
    """Registrar usuario en Cognito y sincronizar con BD local"""
    
    try:
        # 1. Registrar en Cognito
        cognito_result = await cognito_service.register_user(user_data)
        
        # 2. Guardar en BD local
        db_user = User(
            cognito_sub=cognito_result["user_sub"],
            username=cognito_result["username"],
            email=user_data.email,
            full_name=user_data.full_name,
            created_at=datetime.utcnow(),
            is_verified=False
        )
        
        db.add(db_user)
        db.commit()
        
        return {
            "cognito": cognito_result,
            "db_user": db_user
        }
        
    except Exception as e:
        db.rollback()
        # Si falla BD, intentar eliminar de Cognito
        # (implementar lógica de rollback)
        raise e
```

### Webhook para Eventos de Cognito

```python
@app.post("/webhooks/cognito/post-confirmation")
async def cognito_post_confirmation_webhook(event: dict):
    """Webhook llamado por Cognito después de confirmar usuario"""
    
    # Cognito envía eventos en este formato
    if event.get("triggerSource") == "PostConfirmation_ConfirmSignUp":
        user_attributes = event["request"]["userAttributes"]
        
        # Actualizar usuario en BD como verificado
        # Enviar email de bienvenida
        # Crear perfil inicial
        
        print(f"Usuario confirmado: {user_attributes['email']}")
    
    # Siempre retornar el evento
    return event
```

### Testing con Mocks

```python
import pytest
from unittest.mock import Mock, patch

@pytest.mark.asyncio
async def test_register_user():
    """Test de registro con mock de Cognito"""
    
    # Mock del servicio
    mock_cognito = Mock()
    mock_cognito.register_user.return_value = {
        "user_sub": "123-456-789",
        "username": "test_user",
        "email": "test@example.com",
        "confirmation_required": True
    }
    
    # Ejecutar test
    user_data = UserRegister(
        email="test@example.com",
        password="Test123!",
        full_name="Test User"
    )
    
    result = await mock_cognito.register_user(user_data)
    
    # Verificar
    assert result["user_sub"] == "123-456-789"
    assert result["confirmation_required"] == True
    mock_cognito.register_user.assert_called_once_with(user_data)
```

## Notas Importantes

1. **Seguridad**: Siempre valida y sanitiza las entradas del usuario
2. **Tokens**: Los access tokens expiran (por defecto en 1 hora), usa refresh tokens para renovar
3. **Errores**: No reveles información sensible en mensajes de error
4. **Async**: Todas las funciones del servicio son asíncronas
5. **Límites**: AWS Cognito tiene límites de rate, implementa retry con backoff
6. **Logs**: Registra eventos importantes para auditoría

## Referencias

- [Documentación de AWS Cognito](https://docs.aws.amazon.com/cognito/)
- [Documentación de pycognito](https://github.com/pvizeli/pycognito)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)