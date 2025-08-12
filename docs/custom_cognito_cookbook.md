# Custom Cognito Cookbook - Recetas y Casos de Uso

Esta guía contiene recetas prácticas y casos de uso comunes para implementar autenticación con AWS Cognito.

## Tabla de Contenidos

1. [Aplicación FastAPI Completa](#aplicación-fastapi-completa)
2. [Sistema de Autenticación con React](#sistema-de-autenticación-con-react)
3. [CLI para Gestión de Usuarios](#cli-para-gestión-de-usuarios)
4. [Migración desde Auth Existente](#migración-desde-auth-existente)
5. [Implementación de SSO](#implementación-de-sso)
6. [Rate Limiting y Throttling](#rate-limiting-y-throttling)
7. [Monitoreo y Métricas](#monitoreo-y-métricas)

## Aplicación FastAPI Completa

### Estructura del Proyecto

```
my-api/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── routes.py
│   │   ├── dependencies.py
│   │   └── utils.py
│   ├── models/
│   │   └── user.py
│   └── services/
│       └── cognito_wrapper.py
├── .env
└── requirements.txt
```

### main.py - Aplicación Principal

```python
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from contextlib import asynccontextmanager

from app.config import settings
from app.auth.routes import auth_router
from custom_cognito import CognitoService

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Lifespan para inicialización
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Iniciando aplicación...")
    app.state.cognito = CognitoService(settings)
    yield
    # Shutdown
    logger.info("Cerrando aplicación...")

# Crear app
app = FastAPI(
    title="Mi API con Cognito",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir rutas
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])

# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "api"}

# Manejador global de errores
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Error no manejado: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Error interno del servidor"}
    )
```

### auth/routes.py - Rutas de Autenticación

```python
from fastapi import APIRouter, Depends, HTTPException, Response, Request, status
from typing import Optional
import logging

from custom_cognito.schemas import UserRegister, UserLogin
from app.auth.dependencies import get_cognito_service, get_current_user
from app.auth.utils import create_response_with_cookie

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserRegister,
    cognito = Depends(get_cognito_service)
):
    """Registrar nuevo usuario"""
    try:
        result = await cognito.register_user(user_data)
        
        # Log para auditoría
        logger.info(f"Nuevo usuario registrado: {user_data.email}")
        
        return {
            "message": "Usuario registrado exitosamente. Revisa tu email.",
            "data": {
                "email": result["email"],
                "requires_confirmation": result["confirmation_required"]
            }
        }
    except ValueError as e:
        logger.warning(f"Error en registro: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/login")
async def login(
    credentials: UserLogin,
    response: Response,
    cognito = Depends(get_cognito_service)
):
    """Login de usuario"""
    try:
        tokens = await cognito.login(
            credentials.email,
            credentials.password
        )
        
        # Crear respuesta con cookies
        return create_response_with_cookie(
            response,
            tokens,
            message="Login exitoso"
        )
        
    except ValueError as e:
        # Incrementar contador de intentos fallidos
        logger.warning(f"Login fallido para {credentials.email}: {e}")
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )

@router.post("/confirm-email")
async def confirm_email(
    email: str,
    code: str,
    cognito = Depends(get_cognito_service)
):
    """Confirmar email con código"""
    try:
        await cognito.confirm_email(email, code)
        
        logger.info(f"Email confirmado: {email}")
        
        return {
            "message": "Email confirmado exitosamente"
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/refresh")
async def refresh_token(
    request: Request,
    response: Response,
    cognito = Depends(get_cognito_service)
):
    """Renovar tokens usando refresh token"""
    # Obtener refresh token de cookie
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se encontró refresh token"
        )
    
    try:
        new_tokens = await cognito.refresh_tokens(refresh_token)
        
        return {
            "access_token": new_tokens["access_token"],
            "id_token": new_tokens["id_token"],
            "expires_in": new_tokens["expires_in"]
        }
        
    except Exception as e:
        logger.error(f"Error al renovar tokens: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado"
        )

@router.post("/logout")
async def logout(
    response: Response,
    current_user: dict = Depends(get_current_user),
    cognito = Depends(get_cognito_service)
):
    """Logout de usuario"""
    try:
        # Logout en Cognito
        await cognito.logout(current_user["access_token"])
        
        # Eliminar cookies
        response.delete_cookie("refresh_token")
        response.delete_cookie("session_id")
        
        logger.info(f"Usuario deslogueado: {current_user['email']}")
        
        return {"message": "Logout exitoso"}
        
    except Exception as e:
        # Aunque falle, eliminar cookies
        response.delete_cookie("refresh_token")
        response.delete_cookie("session_id")
        
        return {"message": "Logout exitoso"}

@router.get("/me")
async def get_current_user_info(
    current_user: dict = Depends(get_current_user)
):
    """Obtener información del usuario actual"""
    return {
        "email": current_user["email"],
        "name": current_user.get("name", ""),
        "sub": current_user["sub"],
        "email_verified": current_user.get("email_verified", False),
        "groups": current_user.get("cognito:groups", [])
    }
```

### auth/dependencies.py - Dependencies de FastAPI

```python
from fastapi import Depends, HTTPException, Request, status
from typing import Optional
import redis
import json

from custom_cognito import CognitoService, get_current_user as cognito_get_user
from app.config import settings

# Cliente Redis para caché (opcional)
redis_client = redis.from_url(settings.redis_url) if settings.redis_url else None

def get_cognito_service(request: Request) -> CognitoService:
    """Obtener servicio de Cognito desde app state"""
    return request.app.state.cognito

async def get_current_user_cached(
    request: Request,
    user = Depends(cognito_get_user)
) -> dict:
    """Obtener usuario actual con caché"""
    if not redis_client:
        return user
    
    # Intentar obtener de caché
    cache_key = f"user:{user['sub']}"
    cached = redis_client.get(cache_key)
    
    if cached:
        return json.loads(cached)
    
    # Guardar en caché por 5 minutos
    redis_client.setex(
        cache_key,
        300,  # 5 minutos
        json.dumps(user)
    )
    
    return user

# Dependency para requerir email verificado
async def require_verified_email(
    current_user: dict = Depends(get_current_user_cached)
) -> dict:
    """Requerir que el email esté verificado"""
    if not current_user.get("email_verified", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email no verificado"
        )
    return current_user

# Dependency para requerir roles específicos
def require_role(role: str):
    """Factory para crear dependency que requiere un rol"""
    async def role_checker(
        current_user: dict = Depends(get_current_user_cached)
    ) -> dict:
        user_groups = current_user.get("cognito:groups", [])
        
        if role not in user_groups:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Se requiere el rol: {role}"
            )
        
        return current_user
    
    return role_checker

# Aliases comunes
require_admin = require_role("admin")
require_moderator = require_role("moderator")
```

## Sistema de Autenticación con React

### Hook de Autenticación

```typescript
// useAuth.ts
import { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

interface AuthContextType {
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  confirmEmail: (email: string, code: string) => Promise<void>;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [accessToken, setAccessToken] = useState<string | null>(null);

  // Configurar interceptor de axios
  useEffect(() => {
    const requestInterceptor = axios.interceptors.request.use(
      (config) => {
        if (accessToken) {
          config.headers.Authorization = `Bearer ${accessToken}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    const responseInterceptor = axios.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;

        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;

          try {
            const response = await axios.post('/api/auth/refresh');
            setAccessToken(response.data.access_token);
            originalRequest.headers.Authorization = `Bearer ${response.data.access_token}`;
            return axios(originalRequest);
          } catch (refreshError) {
            // Refresh falló, hacer logout
            await logout();
            return Promise.reject(refreshError);
          }
        }

        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.request.eject(requestInterceptor);
      axios.interceptors.response.eject(responseInterceptor);
    };
  }, [accessToken]);

  // Verificar autenticación al cargar
  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    try {
      const response = await axios.get('/api/auth/me');
      setUser(response.data);
    } catch (error) {
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string) => {
    const response = await axios.post('/api/auth/login', { email, password });
    setAccessToken(response.data.data.access_token);
    await checkAuth();
  };

  const logout = async () => {
    try {
      await axios.post('/api/auth/logout');
    } finally {
      setUser(null);
      setAccessToken(null);
    }
  };

  const register = async (data: RegisterData) => {
    await axios.post('/api/auth/register', data);
  };

  const confirmEmail = async (email: string, code: string) => {
    await axios.post('/api/auth/confirm-email', { email, code });
  };

  return (
    <AuthContext.Provider value={{
      user,
      login,
      logout,
      register,
      confirmEmail,
      isLoading
    }}>
      {children}
    </AuthContext.Provider>
  );
};
```

### Componente de Login

```typescript
// LoginForm.tsx
import { useState } from 'react';
import { useAuth } from './useAuth';
import { useNavigate } from 'react-router-dom';

export const LoginForm: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      await login(email, password);
      navigate('/dashboard');
    } catch (error: any) {
      const message = error.response?.data?.detail || 'Error al iniciar sesión';
      setError(message);
      
      // Manejar casos específicos
      if (message.includes('Email not verified')) {
        navigate(`/confirm-email?email=${encodeURIComponent(email)}`);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && (
        <div className="alert alert-danger">{error}</div>
      )}
      
      <div className="form-group">
        <label>Email</label>
        <input
          type="email"
          className="form-control"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
      </div>

      <div className="form-group">
        <label>Contraseña</label>
        <input
          type="password"
          className="form-control"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </div>

      <button 
        type="submit" 
        className="btn btn-primary"
        disabled={isLoading}
      >
        {isLoading ? 'Iniciando sesión...' : 'Iniciar Sesión'}
      </button>
    </form>
  );
};
```

## CLI para Gestión de Usuarios

### cli.py - Herramienta de Línea de Comandos

```python
#!/usr/bin/env python3
"""
CLI para gestión de usuarios Cognito
"""
import click
import asyncio
from tabulate import tabulate
from custom_cognito import CognitoService
from custom_cognito.config import Settings
from custom_cognito.schemas import UserRegister

# Inicializar servicio
settings = Settings()
cognito = CognitoService(settings)

@click.group()
def cli():
    """Herramienta CLI para gestión de usuarios Cognito"""
    pass

@cli.command()
@click.option('--email', prompt=True, help='Email del usuario')
@click.option('--password', prompt=True, hide_input=True, help='Contraseña')
@click.option('--name', prompt=True, help='Nombre completo')
@click.option('--phone', help='Número de teléfono')
def create_user(email, password, name, phone):
    """Crear nuevo usuario"""
    async def _create():
        try:
            user_data = UserRegister(
                email=email,
                password=password,
                full_name=name,
                phone_number=phone
            )
            
            result = await cognito.register_user(user_data)
            
            click.echo(click.style("✓ Usuario creado exitosamente", fg="green"))
            click.echo(f"Username: {result['username']}")
            click.echo(f"User Sub: {result['user_sub']}")
            
            if result['confirmation_required']:
                click.echo(click.style(
                    "⚠ Se requiere confirmación por email", 
                    fg="yellow"
                ))
                
        except Exception as e:
            click.echo(click.style(f"✗ Error: {e}", fg="red"))
            
    asyncio.run(_create())

@cli.command()
def list_users():
    """Listar todos los usuarios"""
    async def _list():
        try:
            users = []
            pagination_token = None
            
            while True:
                params = {
                    'UserPoolId': settings.cognito_user_pool_id,
                    'Limit': 60
                }
                
                if pagination_token:
                    params['PaginationToken'] = pagination_token
                
                response = cognito.client.list_users(**params)
                
                for user in response['Users']:
                    # Extraer atributos
                    attrs = {
                        attr['Name']: attr['Value'] 
                        for attr in user.get('Attributes', [])
                    }
                    
                    users.append({
                        'Username': user['Username'][:20] + '...' if len(user['Username']) > 20 else user['Username'],
                        'Email': attrs.get('email', 'N/A'),
                        'Name': attrs.get('name', 'N/A'),
                        'Status': user['UserStatus'],
                        'Created': user['UserCreateDate'].strftime('%Y-%m-%d')
                    })
                
                pagination_token = response.get('PaginationToken')
                if not pagination_token:
                    break
            
            if users:
                click.echo(tabulate(users, headers='keys', tablefmt='grid'))
                click.echo(f"\nTotal: {len(users)} usuarios")
            else:
                click.echo("No se encontraron usuarios")
                
        except Exception as e:
            click.echo(click.style(f"✗ Error: {e}", fg="red"))
            
    asyncio.run(_list())

@cli.command()
@click.argument('email')
def disable_user(email):
    """Desactivar un usuario"""
    if click.confirm(f'¿Estás seguro de desactivar a {email}?'):
        async def _disable():
            try:
                # Buscar username por email
                username = cognito._get_username_by_email(email)
                
                if not username:
                    click.echo(click.style(
                        f"✗ Usuario no encontrado: {email}", 
                        fg="red"
                    ))
                    return
                
                cognito.client.admin_disable_user(
                    UserPoolId=settings.cognito_user_pool_id,
                    Username=username
                )
                
                click.echo(click.style(
                    f"✓ Usuario desactivado: {email}", 
                    fg="green"
                ))
                
            except Exception as e:
                click.echo(click.style(f"✗ Error: {e}", fg="red"))
                
        asyncio.run(_disable())

@cli.command()
@click.argument('email')
@click.argument('code')
def confirm_user(email, code):
    """Confirmar email de usuario"""
    async def _confirm():
        try:
            await cognito.confirm_email(email, code)
            click.echo(click.style(
                f"✓ Email confirmado: {email}", 
                fg="green"
            ))
        except Exception as e:
            click.echo(click.style(f"✗ Error: {e}", fg="red"))
            
    asyncio.run(_confirm())

@cli.command()
@click.option('--status', help='Filtrar por estado')
@click.option('--export', help='Exportar a archivo CSV')
def report(status, export):
    """Generar reporte de usuarios"""
    async def _report():
        try:
            users = []
            pagination_token = None
            
            while True:
                params = {
                    'UserPoolId': settings.cognito_user_pool_id,
                    'Limit': 60
                }
                
                if pagination_token:
                    params['PaginationToken'] = pagination_token
                
                response = cognito.client.list_users(**params)
                
                for user in response['Users']:
                    if status and user['UserStatus'] != status:
                        continue
                        
                    attrs = {
                        attr['Name']: attr['Value'] 
                        for attr in user.get('Attributes', [])
                    }
                    
                    users.append({
                        'username': user['Username'],
                        'email': attrs.get('email', ''),
                        'name': attrs.get('name', ''),
                        'status': user['UserStatus'],
                        'created': user['UserCreateDate'].isoformat(),
                        'modified': user['UserLastModifiedDate'].isoformat(),
                        'enabled': user['Enabled'],
                        'email_verified': attrs.get('email_verified', 'false')
                    })
                
                pagination_token = response.get('PaginationToken')
                if not pagination_token:
                    break
            
            # Estadísticas
            total = len(users)
            confirmed = sum(1 for u in users if u['status'] == 'CONFIRMED')
            unconfirmed = sum(1 for u in users if u['status'] == 'UNCONFIRMED')
            
            click.echo("=== REPORTE DE USUARIOS ===")
            click.echo(f"Total: {total}")
            click.echo(f"Confirmados: {confirmed}")
            click.echo(f"Sin confirmar: {unconfirmed}")
            
            if export:
                import csv
                
                with open(export, 'w', newline='') as f:
                    if users:
                        writer = csv.DictWriter(f, fieldnames=users[0].keys())
                        writer.writeheader()
                        writer.writerows(users)
                        
                click.echo(click.style(
                    f"\n✓ Exportado a: {export}", 
                    fg="green"
                ))
                
        except Exception as e:
            click.echo(click.style(f"✗ Error: {e}", fg="red"))
            
    asyncio.run(_report())

if __name__ == '__main__':
    cli()
```

### Uso del CLI

```bash
# Instalar dependencias
pip install click tabulate

# Hacer ejecutable
chmod +x cli.py

# Ver ayuda
./cli.py --help

# Crear usuario
./cli.py create-user

# Listar usuarios
./cli.py list-users

# Desactivar usuario
./cli.py disable-user usuario@ejemplo.com

# Generar reporte
./cli.py report --status CONFIRMED --export usuarios.csv
```

## Migración desde Auth Existente

### Script de Migración

```python
"""
Script para migrar usuarios desde sistema existente a Cognito
"""
import asyncio
import csv
from typing import List, Dict
import logging
from custom_cognito import CognitoService
from custom_cognito.config import Settings
from custom_cognito.schemas import UserRegister

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UserMigrator:
    def __init__(self):
        self.settings = Settings()
        self.cognito = CognitoService(self.settings)
        self.results = {
            'success': 0,
            'failed': 0,
            'skipped': 0,
            'errors': []
        }
    
    async def migrate_user(self, user_data: Dict) -> bool:
        """Migrar un usuario individual"""
        try:
            # Verificar si ya existe
            existing = self.cognito._get_username_by_email(user_data['email'])
            if existing:
                logger.info(f"Usuario ya existe: {user_data['email']}")
                self.results['skipped'] += 1
                return False
            
            # Crear usuario con contraseña temporal
            temp_password = self.generate_temp_password()
            
            user = UserRegister(
                email=user_data['email'],
                password=temp_password,
                full_name=user_data.get('name', ''),
                phone_number=user_data.get('phone')
            )
            
            # Registrar en Cognito
            result = await self.cognito.register_user(user)
            
            # Auto-confirmar si es necesario (requiere permisos admin)
            if result['confirmation_required']:
                self.cognito.client.admin_confirm_sign_up(
                    UserPoolId=self.settings.cognito_user_pool_id,
                    Username=result['username']
                )
            
            # Forzar cambio de contraseña en primer login
            self.cognito.client.admin_set_user_password(
                UserPoolId=self.settings.cognito_user_pool_id,
                Username=result['username'],
                Password=temp_password,
                Permanent=False  # Requiere cambio
            )
            
            logger.info(f"Usuario migrado: {user_data['email']}")
            self.results['success'] += 1
            
            # Enviar email de bienvenida con instrucciones
            await self.send_migration_email(
                user_data['email'], 
                temp_password
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error migrando {user_data['email']}: {e}")
            self.results['failed'] += 1
            self.results['errors'].append({
                'email': user_data['email'],
                'error': str(e)
            })
            return False
    
    def generate_temp_password(self) -> str:
        """Generar contraseña temporal segura"""
        import secrets
        import string
        
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(12))
        
        # Asegurar que cumple requisitos
        return f"Temp-{password}1!"
    
    async def send_migration_email(self, email: str, temp_password: str):
        """Enviar email con instrucciones de migración"""
        # Implementar envío de email
        # Por ejemplo, usando SendGrid, SES, etc.
        pass
    
    async def migrate_from_csv(self, csv_file: str):
        """Migrar usuarios desde archivo CSV"""
        users = []
        
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                users.append(row)
        
        logger.info(f"Iniciando migración de {len(users)} usuarios...")
        
        # Procesar en lotes para no sobrecargar
        batch_size = 10
        
        for i in range(0, len(users), batch_size):
            batch = users[i:i + batch_size]
            
            tasks = [
                self.migrate_user(user) 
                for user in batch
            ]
            
            await asyncio.gather(*tasks)
            
            # Pausa entre lotes
            if i + batch_size < len(users):
                await asyncio.sleep(1)
        
        # Mostrar resultados
        logger.info("=== RESULTADOS DE MIGRACIÓN ===")
        logger.info(f"Exitosos: {self.results['success']}")
        logger.info(f"Fallidos: {self.results['failed']}")
        logger.info(f"Omitidos: {self.results['skipped']}")
        
        if self.results['errors']:
            logger.error("Errores encontrados:")
            for error in self.results['errors']:
                logger.error(f"  - {error['email']}: {error['error']}")
    
    async def migrate_from_database(self, connection_string: str):
        """Migrar usuarios desde base de datos existente"""
        from sqlalchemy import create_engine, text
        
        engine = create_engine(connection_string)
        
        with engine.connect() as conn:
            # Ajustar query según tu esquema
            result = conn.execute(text("""
                SELECT 
                    email,
                    full_name as name,
                    phone_number as phone,
                    created_at
                FROM users
                WHERE active = true
            """))
            
            users = [dict(row) for row in result]
        
        logger.info(f"Encontrados {len(users)} usuarios para migrar")
        
        for user in users:
            await self.migrate_user(user)
            # Throttling
            await asyncio.sleep(0.1)

# Ejecutar migración
async def main():
    migrator = UserMigrator()
    
    # Opción 1: Desde CSV
    await migrator.migrate_from_csv('usuarios.csv')
    
    # Opción 2: Desde BD
    # await migrator.migrate_from_database(
    #     'postgresql://user:pass@localhost/olddb'
    # )

if __name__ == '__main__':
    asyncio.run(main())
```

## Implementación de SSO

### SSO con SAML

```python
"""
Integración de Cognito con SAML para SSO
"""
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse
import base64
import xml.etree.ElementTree as ET

router = APIRouter()

@router.get("/sso/saml/login")
async def saml_login(request: Request):
    """Iniciar login SAML"""
    # Cognito maneja automáticamente SAML si está configurado
    # Redirigir al endpoint de Cognito
    cognito_domain = "tu-dominio.auth.region.amazoncognito.com"
    client_id = settings.cognito_app_client_id
    redirect_uri = f"{settings.frontend_url}/auth/callback"
    
    saml_url = (
        f"https://{cognito_domain}/oauth2/authorize?"
        f"identity_provider=TuProveedorSAML&"
        f"redirect_uri={redirect_uri}&"
        f"response_type=code&"
        f"client_id={client_id}&"
        f"scope=openid email profile"
    )
    
    return RedirectResponse(url=saml_url)

@router.post("/sso/saml/callback")
async def saml_callback(request: Request):
    """Callback SAML desde Cognito"""
    # Cognito maneja la validación SAML
    # y retorna tokens OAuth2
    form = await request.form()
    code = form.get("code")
    
    if not code:
        raise HTTPException(
            status_code=400,
            detail="No se recibió código de autorización"
        )
    
    # Intercambiar código por tokens
    token_response = await exchange_code_for_tokens(code)
    
    # Crear sesión local
    return create_sso_session(token_response)
```

### SSO con OAuth2/OIDC

```python
"""
Integración con proveedores OAuth2 externos
"""
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config

# Configurar OAuth
config = Config('.env')
oauth = OAuth(config)

# Registrar proveedores
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

@router.get('/sso/google/login')
async def google_login(request: Request):
    """Iniciar login con Google"""
    redirect_uri = request.url_for('google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get('/sso/google/callback')
async def google_callback(request: Request):
    """Callback de Google"""
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        
        # Verificar si el usuario existe en Cognito
        email = user_info['email']
        
        # Opción 1: Crear usuario en Cognito si no existe
        existing = cognito._get_username_by_email(email)
        
        if not existing:
            # Crear usuario con contraseña aleatoria
            import secrets
            
            user_data = UserRegister(
                email=email,
                password=secrets.token_urlsafe(32),
                full_name=user_info.get('name', ''),
            )
            
            result = await cognito.register_user(user_data)
            
            # Auto-confirmar
            cognito.client.admin_confirm_sign_up(
                UserPoolId=settings.cognito_user_pool_id,
                Username=result['username']
            )
        
        # Opción 2: Crear sesión directa (bypass Cognito)
        # return create_federated_session(user_info)
        
        # Generar tokens propios o redirigir a login
        return {"message": "SSO exitoso", "user": user_info}
        
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Error en SSO: {str(e)}"
        )
```

## Rate Limiting y Throttling

### Implementación con Redis

```python
"""
Rate limiting para proteger endpoints de autenticación
"""
import time
from typing import Optional
import redis
from fastapi import Request, HTTPException, status

class RateLimiter:
    def __init__(
        self, 
        redis_client: redis.Redis,
        max_requests: int = 10,
        window_seconds: int = 60
    ):
        self.redis = redis_client
        self.max_requests = max_requests
        self.window_seconds = window_seconds
    
    async def check_rate_limit(
        self, 
        key: str,
        max_requests: Optional[int] = None,
        window: Optional[int] = None
    ) -> tuple[bool, dict]:
        """Verificar rate limit"""
        max_req = max_requests or self.max_requests
        window_sec = window or self.window_seconds
        
        # Usar sliding window con Redis
        now = time.time()
        pipeline = self.redis.pipeline()
        
        # Eliminar entradas viejas
        pipeline.zremrangebyscore(key, 0, now - window_sec)
        
        # Contar requests en la ventana
        pipeline.zcard(key)
        
        # Agregar request actual
        pipeline.zadd(key, {str(now): now})
        
        # Establecer TTL
        pipeline.expire(key, window_sec)
        
        results = pipeline.execute()
        request_count = results[1]
        
        if request_count > max_req:
            # Calcular tiempo hasta que se pueda reintentar
            oldest = self.redis.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = int(window_sec - (now - oldest[0][1]))
            else:
                retry_after = window_sec
            
            return False, {
                'limit': max_req,
                'remaining': 0,
                'retry_after': retry_after
            }
        
        return True, {
            'limit': max_req,
            'remaining': max_req - request_count,
            'retry_after': 0
        }

# Dependency para rate limiting
async def rate_limit_dependency(
    request: Request,
    endpoint: str = "general"
):
    """Dependency de FastAPI para rate limiting"""
    # Obtener IP del cliente
    client_ip = request.client.host
    
    # Diferentes límites por endpoint
    limits = {
        'login': (5, 300),      # 5 intentos en 5 minutos
        'register': (3, 3600),  # 3 registros por hora
        'password_reset': (3, 900),  # 3 intentos en 15 minutos
        'general': (100, 60),   # 100 requests por minuto
    }
    
    max_requests, window = limits.get(endpoint, limits['general'])
    
    # Crear key única
    key = f"rate_limit:{endpoint}:{client_ip}"
    
    limiter = RateLimiter(redis_client)
    allowed, info = await limiter.check_rate_limit(
        key, 
        max_requests, 
        window
    )
    
    # Agregar headers de rate limit
    request.state.rate_limit_headers = {
        'X-RateLimit-Limit': str(info['limit']),
        'X-RateLimit-Remaining': str(info['remaining']),
        'X-RateLimit-Reset': str(int(time.time() + info['retry_after']))
    }
    
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados intentos. Intenta más tarde.",
            headers={
                'Retry-After': str(info['retry_after'])
            }
        )

# Uso en endpoints
@router.post(
    "/login",
    dependencies=[Depends(lambda r: rate_limit_dependency(r, "login"))]
)
async def login_with_rate_limit(
    credentials: UserLogin,
    response: Response,
    request: Request,
    cognito = Depends(get_cognito_service)
):
    """Login con rate limiting"""
    # Agregar headers de rate limit a la respuesta
    if hasattr(request.state, 'rate_limit_headers'):
        for key, value in request.state.rate_limit_headers.items():
            response.headers[key] = value
    
    # Continuar con login normal
    # ...
```

### Middleware Global de Rate Limiting

```python
from starlette.middleware.base import BaseHTTPMiddleware

class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, redis_client: redis.Redis):
        super().__init__(app)
        self.limiter = RateLimiter(redis_client)
    
    async def dispatch(self, request: Request, call_next):
        # Skip para rutas excluidas
        excluded_paths = ['/health', '/docs', '/openapi.json']
        
        if request.url.path in excluded_paths:
            return await call_next(request)
        
        # Rate limit global por IP
        client_ip = request.client.host
        key = f"global_rate_limit:{client_ip}"
        
        allowed, info = await self.limiter.check_rate_limit(
            key,
            max_requests=1000,  # 1000 requests
            window=3600         # por hora
        )
        
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit excedido"},
                headers={'Retry-After': str(info['retry_after'])}
            )
        
        response = await call_next(request)
        
        # Agregar headers informativos
        response.headers['X-RateLimit-Limit'] = str(info['limit'])
        response.headers['X-RateLimit-Remaining'] = str(info['remaining'])
        
        return response

# Agregar a la app
app.add_middleware(
    GlobalRateLimitMiddleware,
    redis_client=redis_client
)
```

## Monitoreo y Métricas

### Integración con Prometheus

```python
"""
Métricas de autenticación para Prometheus
"""
from prometheus_client import Counter, Histogram, Gauge
import time

# Definir métricas
auth_requests_total = Counter(
    'auth_requests_total',
    'Total de requests de autenticación',
    ['method', 'endpoint', 'status']
)

auth_duration_seconds = Histogram(
    'auth_duration_seconds',
    'Duración de requests de autenticación',
    ['method', 'endpoint']
)

active_sessions = Gauge(
    'active_sessions_total',
    'Número de sesiones activas'
)

failed_login_attempts = Counter(
    'failed_login_attempts_total',
    'Intentos de login fallidos',
    ['reason']
)

# Decorator para métricas
def track_auth_metrics(endpoint: str):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            status = 'success'
            
            try:
                result = await func(*args, **kwargs)
                return result
                
            except HTTPException as e:
                status = 'error'
                
                # Rastrear razones de fallo
                if endpoint == 'login' and e.status_code == 401:
                    reason = 'invalid_credentials'
                    if 'Email not verified' in str(e.detail):
                        reason = 'email_not_verified'
                    elif 'Password change required' in str(e.detail):
                        reason = 'password_change_required'
                    
                    failed_login_attempts.labels(reason=reason).inc()
                
                raise
                
            except Exception:
                status = 'error'
                raise
                
            finally:
                # Registrar métricas
                duration = time.time() - start_time
                
                auth_requests_total.labels(
                    method='POST',
                    endpoint=endpoint,
                    status=status
                ).inc()
                
                auth_duration_seconds.labels(
                    method='POST',
                    endpoint=endpoint
                ).observe(duration)
        
        return wrapper
    return decorator

# Uso en endpoints
@router.post("/login")
@track_auth_metrics("login")
async def login_with_metrics(
    credentials: UserLogin,
    cognito = Depends(get_cognito_service)
):
    # Login logic...
    pass

# Endpoint para métricas
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

@app.get("/metrics")
async def metrics():
    return Response(
        generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
```

### Logging Estructurado

```python
"""
Logging estructurado para auditoría
"""
import structlog
from typing import Any

# Configurar structlog
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

# Logger para auditoría
audit_logger = structlog.get_logger("auth.audit")

class AuthAuditor:
    """Clase para auditar eventos de autenticación"""
    
    @staticmethod
    def log_login_attempt(
        email: str,
        ip_address: str,
        user_agent: str,
        success: bool,
        reason: Optional[str] = None
    ):
        audit_logger.info(
            "login_attempt",
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            reason=reason,
            timestamp=time.time()
        )
    
    @staticmethod
    def log_user_registration(
        email: str,
        ip_address: str,
        success: bool,
        error: Optional[str] = None
    ):
        audit_logger.info(
            "user_registration",
            email=email,
            ip_address=ip_address,
            success=success,
            error=error,
            timestamp=time.time()
        )
    
    @staticmethod
    def log_password_reset(
        email: str,
        ip_address: str,
        step: str  # 'initiated' | 'confirmed'
    ):
        audit_logger.info(
            "password_reset",
            email=email,
            ip_address=ip_address,
            step=step,
            timestamp=time.time()
        )
    
    @staticmethod
    def log_token_refresh(
        user_id: str,
        success: bool
    ):
        audit_logger.info(
            "token_refresh",
            user_id=user_id,
            success=success,
            timestamp=time.time()
        )

# Uso en endpoints
@router.post("/login")
async def login_with_audit(
    credentials: UserLogin,
    request: Request,
    cognito = Depends(get_cognito_service)
):
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        tokens = await cognito.login(
            credentials.email,
            credentials.password
        )
        
        # Log exitoso
        AuthAuditor.log_login_attempt(
            email=credentials.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=True
        )
        
        return tokens
        
    except ValueError as e:
        # Log fallido
        AuthAuditor.log_login_attempt(
            email=credentials.email,
            ip_address=client_ip,
            user_agent=user_agent,
            success=False,
            reason=str(e)
        )
        
        raise HTTPException(
            status_code=401,
            detail=str(e)
        )
```

### Dashboard de Monitoreo

```python
"""
Dashboard simple para monitorear autenticación
"""
from fastapi import APIRouter, Depends
from datetime import datetime, timedelta
import json

monitoring_router = APIRouter(
    prefix="/api/monitoring",
    dependencies=[Depends(require_admin)]
)

@monitoring_router.get("/auth/stats")
async def get_auth_stats():
    """Obtener estadísticas de autenticación"""
    # Calcular estadísticas desde Redis/BD
    
    now = datetime.utcnow()
    
    stats = {
        'last_24h': {
            'total_logins': await count_events('login', timedelta(days=1)),
            'failed_logins': await count_events('login_failed', timedelta(days=1)),
            'new_registrations': await count_events('registration', timedelta(days=1)),
            'password_resets': await count_events('password_reset', timedelta(days=1)),
        },
        'last_7d': {
            'total_logins': await count_events('login', timedelta(days=7)),
            'failed_logins': await count_events('login_failed', timedelta(days=7)),
            'new_registrations': await count_events('registration', timedelta(days=7)),
            'active_users': await count_unique_users(timedelta(days=7)),
        },
        'current': {
            'active_sessions': await count_active_sessions(),
            'users_online': await count_users_online(),
        }
    }
    
    return stats

@monitoring_router.get("/auth/recent-activity")
async def get_recent_activity(
    limit: int = 50
):
    """Obtener actividad reciente"""
    # Obtener logs recientes desde Redis/BD
    
    activities = []
    
    # Ejemplo de estructura
    for i in range(limit):
        activities.append({
            'timestamp': (datetime.utcnow() - timedelta(minutes=i)).isoformat(),
            'event': 'login',
            'user': f'user{i}@example.com',
            'ip': f'192.168.1.{i}',
            'success': i % 3 != 0
        })
    
    return activities

@monitoring_router.get("/auth/failed-attempts")
async def get_failed_attempts(
    hours: int = 24
):
    """Obtener intentos fallidos recientes"""
    # Consultar logs de intentos fallidos
    
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Agrupar por usuario/IP
    failed_attempts = {}
    
    # Lógica para obtener de BD/logs
    
    return {
        'period_hours': hours,
        'total_attempts': sum(failed_attempts.values()),
        'by_user': failed_attempts,
        'suspicious_ips': identify_suspicious_ips(failed_attempts)
    }

# Helpers
async def count_events(event_type: str, period: timedelta) -> int:
    """Contar eventos en un período"""
    # Implementar consulta a BD/Redis
    return 0

async def count_unique_users(period: timedelta) -> int:
    """Contar usuarios únicos en un período"""
    # Implementar consulta
    return 0

async def count_active_sessions() -> int:
    """Contar sesiones activas"""
    if redis_client:
        pattern = "session:*"
        cursor = 0
        count = 0
        
        while True:
            cursor, keys = redis_client.scan(
                cursor, 
                match=pattern, 
                count=1000
            )
            count += len(keys)
            
            if cursor == 0:
                break
        
        return count
    
    return 0
```

## Mejores Prácticas y Recomendaciones

### Seguridad

1. **Siempre usa HTTPS** en producción
2. **Implementa rate limiting** en todos los endpoints de auth
3. **Registra todos los eventos** de autenticación para auditoría
4. **Usa cookies httpOnly** para refresh tokens
5. **Implementa CSRF protection** cuando uses cookies
6. **Valida y sanitiza** todas las entradas
7. **No reveles información** en mensajes de error

### Performance

1. **Cachea validaciones JWT** para reducir latencia
2. **Usa connection pooling** para Redis/BD
3. **Implementa retry logic** con exponential backoff
4. **Procesa eventos asincrónicamente** cuando sea posible

### Mantenibilidad

1. **Centraliza la configuración** en un solo lugar
2. **Usa dependency injection** para facilitar testing
3. **Implementa health checks** detallados
4. **Documenta todos los endpoints** con OpenAPI
5. **Mantén logs estructurados** para facilitar debugging

Esta documentación proporciona ejemplos completos y prácticos para implementar un sistema de autenticación robusto con AWS Cognito.