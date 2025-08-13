# AWS Cognito Utilities

Utilidades para trabajar con AWS Cognito User Pools usando boto3, proporcionando una interfaz simple para autenticación y gestión de usuarios.

## Tabla de Contenidos

- [Instalación](#instalación)
- [Configuración](#configuración)
- [Uso Básico](#uso-básico)
- [Funciones Disponibles](#funciones-disponibles)
- [Ejemplos Completos](#ejemplos-completos)
- [Manejo de Errores](#manejo-de-errores)
- [Mejores Prácticas](#mejores-prácticas)

## Instalación

Las utilidades de Cognito están incluidas en el paquete `python-helpers`:

```bash
pip install -e .
```

## Configuración

### Requisitos Previos

1. **Crear un User Pool en AWS Cognito**:
   - Accede a la consola de AWS Cognito
   - Crea un nuevo User Pool con las configuraciones deseadas
   - Anota el `User Pool ID`

2. **Crear un App Client**:
   - En tu User Pool, ve a "App clients"
   - Crea un nuevo App Client
   - Anota el `Client ID` y `Client Secret` (si lo configuras)
   - Habilita el flujo `USER_PASSWORD_AUTH`

3. **Configurar credenciales AWS**:
   ```bash
   export AWS_ACCESS_KEY_ID="tu-access-key"
   export AWS_SECRET_ACCESS_KEY="tu-secret-key"
   export AWS_DEFAULT_REGION="eu-west-1"
   ```

### Configuración con Client Secret

Si tu App Client tiene un secret configurado, todas las operaciones requieren el cálculo del `SECRET_HASH`:

```python
from custom_aws.cognito import register_user

# Con client secret
result = register_user(
    user_pool_id="eu-west-1_XXXXXXXXX",
    client_id="1234567890abcdef",
    email="usuario@ejemplo.com",
    password="ContraseñaSegura123!",
    attributes={"name": "Juan Pérez"},
    client_secret="tu-client-secret"  # Requerido si el App Client tiene secret
)
```

## Uso Básico

### Flujo de Autenticación Completo

```python
from custom_aws.cognito import (
    register_user,
    confirm_user,
    authenticate_user,
    get_user
)

# 1. Registrar un nuevo usuario
result = register_user(
    user_pool_id="eu-west-1_XXXXXXXXX",
    client_id="1234567890abcdef",
    email="usuario@ejemplo.com",
    password="ContraseñaSegura123!",
    attributes={
        "name": "Juan Pérez",
        "phone_number": "+34600123456"
    }
)
print(f"Usuario creado con ID: {result['user_sub']}")
print(f"Confirmación requerida: {result['confirmation_required']}")

# 2. Confirmar el email con el código recibido
confirm_result = confirm_user(
    user_pool_id="eu-west-1_XXXXXXXXX",
    client_id="1234567890abcdef",
    email="usuario@ejemplo.com",
    code="123456"
)
print(confirm_result['message'])

# 3. Iniciar sesión
tokens = authenticate_user(
    user_pool_id="eu-west-1_XXXXXXXXX",
    client_id="1234567890abcdef",
    email="usuario@ejemplo.com",
    password="ContraseñaSegura123!"
)
print(f"Access Token: {tokens['access_token']}")
print(f"El token expira en: {tokens['expires_in']} segundos")

# 4. Obtener información del usuario
user_info = get_user(access_token=tokens['access_token'])
print(f"Usuario: {user_info['username']}")
print(f"Atributos: {user_info['attributes']}")
```

## Funciones Disponibles

### register_user

Registra un nuevo usuario en el User Pool.

```python
register_user(
    user_pool_id: str,
    client_id: str,
    email: str,
    password: str,
    attributes: Optional[Dict[str, str]] = None,
    client_secret: Optional[str] = None,
    region_name: Optional[str] = None
) -> Dict[str, Any]
```

**Parámetros:**
- `user_pool_id`: ID del User Pool de Cognito
- `client_id`: ID del App Client
- `email`: Email del usuario
- `password`: Contraseña (debe cumplir con las políticas del User Pool)
- `attributes`: Atributos adicionales del usuario (name, phone_number, etc.)
- `client_secret`: Secret del App Client (si está configurado)
- `region_name`: Región AWS (por defecto: AWS_DEFAULT_REGION o eu-west-1)

**Retorna:**
```python
{
    "user_sub": "550e8400-e29b-41d4-a716-446655440000",
    "confirmation_required": True,
    "code_delivery_destination": {
        "AttributeName": "email",
        "DeliveryMedium": "EMAIL",
        "Destination": "u***@e***.com"
    }
}
```

### confirm_user

Confirma el registro de un usuario con el código de verificación.

```python
confirm_user(
    user_pool_id: str,
    client_id: str,
    email: str,
    code: str,
    client_secret: Optional[str] = None,
    region_name: Optional[str] = None
) -> Dict[str, Any]
```

### authenticate_user

Autentica un usuario y obtiene tokens JWT.

```python
authenticate_user(
    user_pool_id: str,
    client_id: str,
    email: str,
    password: str,
    client_secret: Optional[str] = None,
    region_name: Optional[str] = None
) -> Dict[str, Any]
```

**Retorna:**
```python
{
    "access_token": "eyJraWQiOiI...",
    "id_token": "eyJraWQiOiI...",
    "refresh_token": "eyJjdHkiOiI...",
    "expires_in": 3600,
    "token_type": "Bearer"
}
```

### refresh_token

Obtiene nuevos tokens usando un refresh token.

```python
refresh_token(
    user_pool_id: str,
    client_id: str,
    refresh_token: str,
    username: Optional[str] = None,  # Requerido si hay client_secret
    client_secret: Optional[str] = None,
    region_name: Optional[str] = None
) -> Dict[str, Any]
```

**Importante**: Si el App Client tiene un secret, debes proporcionar el `username` (email) para calcular el SECRET_HASH.

### forgot_password

Inicia el proceso de recuperación de contraseña.

```python
forgot_password(
    user_pool_id: str,
    client_id: str,
    email: str,
    client_secret: Optional[str] = None,
    region_name: Optional[str] = None
) -> Dict[str, Any]
```

### confirm_forgot_password

Confirma el cambio de contraseña con el código recibido.

```python
confirm_forgot_password(
    user_pool_id: str,
    client_id: str,
    email: str,
    code: str,
    new_password: str,
    client_secret: Optional[str] = None,
    region_name: Optional[str] = None
) -> Dict[str, Any]
```

### get_user

Obtiene información del usuario usando su access token.

```python
get_user(
    access_token: str,
    region_name: Optional[str] = None
) -> Dict[str, Any]
```

**Retorna:**
```python
{
    "username": "usuario@ejemplo.com",
    "attributes": {
        "sub": "550e8400-e29b-41d4-a716-446655440000",
        "email": "usuario@ejemplo.com",
        "email_verified": "true",
        "name": "Juan Pérez",
        "phone_number": "+34600123456"
    },
    "mfa_options": [],
    "preferred_mfa": None,
    "user_mfa_settings": []
}
```

### update_user_attributes

Actualiza los atributos del usuario.

```python
update_user_attributes(
    access_token: str,
    attributes: Dict[str, str],
    region_name: Optional[str] = None
) -> Dict[str, Any]
```

**Ejemplo:**
```python
result = update_user_attributes(
    access_token=tokens['access_token'],
    attributes={
        "name": "Juan Pérez García",
        "phone_number": "+34600999888"
    }
)
```

### delete_user

Elimina la cuenta del usuario.

```python
delete_user(
    access_token: str,
    region_name: Optional[str] = None
) -> Dict[str, Any]
```

### test_cognito_connection

Prueba la conexión con AWS Cognito.

```python
test_cognito_connection(
    user_pool_id: str,
    region_name: Optional[str] = None
) -> Dict[str, Any]
```

## Ejemplos Completos

### Ejemplo 1: Registro con Confirmación Automática

```python
from custom_aws.cognito import register_user, confirm_user, authenticate_user

# Configuración
USER_POOL_ID = "eu-west-1_XXXXXXXXX"
CLIENT_ID = "1234567890abcdef"
CLIENT_SECRET = "tu-client-secret"  # Si aplica

# Registro
try:
    # Registrar usuario
    reg_result = register_user(
        user_pool_id=USER_POOL_ID,
        client_id=CLIENT_ID,
        email="nuevo@ejemplo.com",
        password="SuperSegura123!",
        attributes={"name": "Nuevo Usuario"},
        client_secret=CLIENT_SECRET
    )
    
    print(f"Usuario registrado: {reg_result['user_sub']}")
    
    # Solicitar código de confirmación al usuario
    code = input("Ingresa el código recibido por email: ")
    
    # Confirmar
    confirm_user(
        user_pool_id=USER_POOL_ID,
        client_id=CLIENT_ID,
        email="nuevo@ejemplo.com",
        code=code,
        client_secret=CLIENT_SECRET
    )
    
    print("¡Usuario confirmado exitosamente!")
    
except ValueError as e:
    print(f"Error: {e}")
```

### Ejemplo 2: Gestión de Sesiones con Refresh Token

```python
from custom_aws.cognito import authenticate_user, refresh_token, get_user
import time

# Login inicial
tokens = authenticate_user(
    user_pool_id=USER_POOL_ID,
    client_id=CLIENT_ID,
    email="usuario@ejemplo.com",
    password="ContraseñaSegura123!",
    client_secret=CLIENT_SECRET
)

# Guardar tokens
access_token = tokens['access_token']
refresh_token_value = tokens['refresh_token']
expires_in = tokens['expires_in']

print(f"Token válido por {expires_in} segundos")

# Simular paso del tiempo...
# time.sleep(expires_in + 1)

# Renovar tokens
try:
    new_tokens = refresh_token(
        user_pool_id=USER_POOL_ID,
        client_id=CLIENT_ID,
        refresh_token=refresh_token_value,
        username="usuario@ejemplo.com",  # Requerido con client_secret
        client_secret=CLIENT_SECRET
    )
    
    print("Tokens renovados exitosamente")
    access_token = new_tokens['access_token']
    
except ValueError as e:
    print(f"Error al renovar tokens: {e}")
    # Solicitar nuevo login
```

### Ejemplo 3: Recuperación de Contraseña

```python
from custom_aws.cognito import forgot_password, confirm_forgot_password

# Iniciar recuperación
try:
    result = forgot_password(
        user_pool_id=USER_POOL_ID,
        client_id=CLIENT_ID,
        email="usuario@ejemplo.com",
        client_secret=CLIENT_SECRET
    )
    
    print("Código de recuperación enviado")
    
    # Solicitar código y nueva contraseña
    code = input("Ingresa el código recibido: ")
    new_password = input("Ingresa tu nueva contraseña: ")
    
    # Confirmar cambio
    confirm_forgot_password(
        user_pool_id=USER_POOL_ID,
        client_id=CLIENT_ID,
        email="usuario@ejemplo.com",
        code=code,
        new_password=new_password,
        client_secret=CLIENT_SECRET
    )
    
    print("¡Contraseña actualizada exitosamente!")
    
except ValueError as e:
    print(f"Error: {e}")
```

## Manejo de Errores

Todas las funciones pueden lanzar las siguientes excepciones:

### ValueError

Se lanza para errores de validación y errores de Cognito específicos:

```python
try:
    tokens = authenticate_user(...)
except ValueError as e:
    error_message = str(e)
    if "Email o contraseña incorrectos" in error_message:
        # Credenciales inválidas
    elif "El usuario no ha confirmado su email" in error_message:
        # Usuario no confirmado
    elif "Demasiados intentos" in error_message:
        # Rate limiting
```

### NoCredentialsError

Se lanza cuando no hay credenciales AWS configuradas:

```python
from botocore.exceptions import NoCredentialsError

try:
    result = register_user(...)
except NoCredentialsError:
    print("Por favor configura tus credenciales AWS")
```

### ClientError

Se lanza para otros errores de AWS:

```python
from botocore.exceptions import ClientError

try:
    result = get_user(access_token)
except ClientError as e:
    error_code = e.response['Error']['Code']
    print(f"Error AWS: {error_code}")
```

## Mejores Prácticas

### 1. Seguridad de Contraseñas

Configura políticas de contraseña apropiadas en tu User Pool:

```python
# Las contraseñas deben cumplir con los requisitos del User Pool
# Ejemplo: mínimo 8 caracteres, mayúsculas, minúsculas, números y símbolos
password = "SuperSegura123!@#"
```

### 2. Manejo de Client Secret

Si tu App Client tiene un secret:

```python
# Siempre proporciona el client_secret
result = authenticate_user(
    user_pool_id=USER_POOL_ID,
    client_id=CLIENT_ID,
    email=email,
    password=password,
    client_secret=CLIENT_SECRET  # No olvides esto
)

# Para refresh_token, también proporciona el username
new_tokens = refresh_token(
    user_pool_id=USER_POOL_ID,
    client_id=CLIENT_ID,
    refresh_token=refresh_token_value,
    username=email,  # Requerido con client_secret
    client_secret=CLIENT_SECRET
)
```

### 3. Almacenamiento Seguro de Tokens

```python
# NO hagas esto:
# tokens_en_texto_plano = tokens

# Mejor práctica: Usa un almacenamiento seguro
# Por ejemplo, en variables de entorno temporales o sistemas de gestión de secretos
import os
os.environ['USER_ACCESS_TOKEN'] = tokens['access_token']

# O usa AWS Secrets Manager
from custom_aws.secrets import get_secret_fields
# Guarda los tokens de forma segura
```

### 4. Gestión de Sesiones

```python
import time
from datetime import datetime, timedelta

class CognitoSession:
    def __init__(self, tokens):
        self.access_token = tokens['access_token']
        self.refresh_token = tokens['refresh_token']
        self.expires_at = datetime.now() + timedelta(seconds=tokens['expires_in'])
    
    def is_expired(self):
        return datetime.now() >= self.expires_at
    
    def get_valid_token(self):
        if self.is_expired():
            # Renovar tokens
            new_tokens = refresh_token(...)
            self.access_token = new_tokens['access_token']
            self.expires_at = datetime.now() + timedelta(seconds=new_tokens['expires_in'])
        return self.access_token
```

### 5. Configuración por Entorno

```python
import os
from custom_aws.cognito import authenticate_user

# Configuración desde variables de entorno
config = {
    'user_pool_id': os.environ.get('COGNITO_USER_POOL_ID'),
    'client_id': os.environ.get('COGNITO_CLIENT_ID'),
    'client_secret': os.environ.get('COGNITO_CLIENT_SECRET'),
    'region_name': os.environ.get('AWS_REGION', 'eu-west-1')
}

# Uso
tokens = authenticate_user(
    user_pool_id=config['user_pool_id'],
    client_id=config['client_id'],
    email=email,
    password=password,
    client_secret=config['client_secret'],
    region_name=config['region_name']
)
```

## Usando CognitoManager para Aplicaciones

La clase `CognitoManager` proporciona una forma más eficiente de trabajar con Cognito cuando necesitas realizar múltiples operaciones, reutilizando el mismo cliente:

### Uso Básico de CognitoManager

```python
from custom_aws.cognito import CognitoManager

# Crear una instancia del manager
manager = CognitoManager(
    user_pool_id="eu-west-1_XXXXXXXXX",
    client_id="1234567890abcdef",
    client_secret="mi-client-secret"  # Opcional
)

# Realizar múltiples operaciones con el mismo cliente
try:
    # Registrar usuario
    result = manager.register_user(
        email="usuario@ejemplo.com",
        password="ContraseñaSegura123!",
        attributes={"name": "Juan Pérez"}
    )
    print(f"Usuario creado: {result['user_sub']}")
    
    # Confirmar usuario
    manager.confirm_user("usuario@ejemplo.com", "123456")
    
    # Autenticar
    tokens = manager.authenticate_user("usuario@ejemplo.com", "ContraseñaSegura123!")
    
    # Obtener información del usuario
    user_info = manager.get_user(tokens['access_token'])
    print(f"Usuario: {user_info['attributes']['email']}")
    
finally:
    # Cerrar el manager cuando ya no se necesite
    manager.close()
```

### Uso con Context Manager

```python
# El cliente se cierra automáticamente al salir del bloque
with CognitoManager(
    user_pool_id="eu-west-1_XXXXXXXXX",
    client_id="1234567890abcdef",
    client_secret="mi-client-secret"
) as manager:
    tokens = manager.authenticate_user("usuario@ejemplo.com", "ContraseñaSegura123!")
    user_info = manager.get_user(tokens['access_token'])
    # Al salir del bloque, el cliente se cierra automáticamente
```

### Ventajas de CognitoManager

1. **Eficiencia**: Reutiliza el mismo cliente para múltiples operaciones
2. **Simplicidad**: No necesitas repetir `user_pool_id` y `client_id` en cada llamada
3. **Gestión de recursos**: Soporte para context manager
4. **Menos código**: Configuración centralizada

### Cuándo usar CognitoManager vs Funciones

**Usa CognitoManager cuando:**
- Necesitas realizar múltiples operaciones de Cognito
- Tu aplicación mantiene estado (como una API o aplicación web)
- Quieres optimizar el rendimiento reutilizando conexiones
- Prefieres una API orientada a objetos

**Usa las funciones individuales cuando:**
- Solo necesitas una operación puntual
- Estás en un script simple o función Lambda
- Prefieres un estilo funcional
- Necesitas máxima flexibilidad en la configuración

## Integración con FastAPI

### Ejemplo con Funciones Individuales

```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from custom_aws.cognito import authenticate_user, get_user

app = FastAPI()
security = HTTPBearer()

# Configuración
USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID')
CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID')
CLIENT_SECRET = os.environ.get('COGNITO_CLIENT_SECRET')

@app.post("/login")
async def login(email: str, password: str):
    try:
        tokens = authenticate_user(
            user_pool_id=USER_POOL_ID,
            client_id=CLIENT_ID,
            email=email,
            password=password,
            client_secret=CLIENT_SECRET
        )
        return {"access_token": tokens['access_token'], "token_type": "Bearer"}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        user = get_user(access_token=credentials.credentials)
        return user
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/profile")
async def profile(user = Depends(get_current_user)):
    return {
        "email": user['attributes']['email'],
        "name": user['attributes'].get('name', ''),
        "verified": user['attributes']['email_verified']
    }
```

### Ejemplo con CognitoManager (Recomendado para APIs)

```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from custom_aws.cognito import CognitoManager
import os

app = FastAPI()
security = HTTPBearer()

# Crear instancia global del manager
cognito_manager = CognitoManager(
    user_pool_id=os.environ.get('COGNITO_USER_POOL_ID'),
    client_id=os.environ.get('COGNITO_CLIENT_ID'),
    client_secret=os.environ.get('COGNITO_CLIENT_SECRET')
)

@app.post("/login")
async def login(email: str, password: str):
    try:
        tokens = cognito_manager.authenticate_user(email, password)
        return {"access_token": tokens['access_token'], "token_type": "Bearer"}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

@app.post("/register")
async def register(email: str, password: str, name: str):
    try:
        result = cognito_manager.register_user(
            email=email,
            password=password,
            attributes={"name": name}
        )
        return {"message": "Usuario registrado", "user_id": result['user_sub']}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        user = cognito_manager.get_user(access_token=credentials.credentials)
        return user
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/profile")
async def profile(user = Depends(get_current_user)):
    return {
        "username": user['username'],
        "email": user['attributes']['email'],
        "name": user['attributes'].get('name', ''),
        "verified": user['attributes'].get('email_verified', 'false')
    }

# Cerrar el manager al apagar la aplicación
@app.on_event("shutdown")
async def shutdown_event():
    cognito_manager.close()
```

## Solución de Problemas

### Error: "Client is configured with secret but SECRET_HASH was not received"

Este error ocurre cuando tu App Client tiene un secret configurado pero no lo estás proporcionando:

```python
# Incorrecto
authenticate_user(
    user_pool_id=USER_POOL_ID,
    client_id=CLIENT_ID,
    email=email,
    password=password
    # Falta client_secret
)

# Correcto
authenticate_user(
    user_pool_id=USER_POOL_ID,
    client_id=CLIENT_ID,
    email=email,
    password=password,
    client_secret=CLIENT_SECRET  # ✓ Incluye el secret
)
```

### Error: "Token is expired"

Los access tokens de Cognito tienen una duración limitada. Usa el refresh token para obtener nuevos tokens:

```python
try:
    user = get_user(access_token=old_token)
except ValueError as e:
    if "expirado" in str(e):
        # Renovar token
        new_tokens = refresh_token(
            user_pool_id=USER_POOL_ID,
            client_id=CLIENT_ID,
            refresh_token=saved_refresh_token,
            username=user_email,  # Si hay client_secret
            client_secret=CLIENT_SECRET
        )
        # Usar el nuevo access token
        user = get_user(access_token=new_tokens['access_token'])
```

### Error: "User pool does not exist"

Verifica que el User Pool ID sea correcto y que esté en la región correcta:

```python
# Verificar conexión
try:
    info = test_cognito_connection(
        user_pool_id="eu-west-1_XXXXXXXXX",
        region_name="eu-west-1"  # Asegúrate de usar la región correcta
    )
    print(f"Conectado a: {info['user_pool_name']}")
except ValueError as e:
    print(f"Error: {e}")
```

## Ver También

- [Documentación de AWS Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/)
- [custom_aws - Documentación general](./custom_aws.md)
- [custom_aws.credentials - Gestión de credenciales](./custom_aws_credentials.md)