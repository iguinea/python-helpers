# Herramientas de Cognito

Este directorio contiene utilidades para gestionar y probar usuarios en AWS Cognito.

## Scripts Disponibles

### Gestión de Usuarios

- **`list_cognito_users.py`**: Lista todos los usuarios del User Pool
- **`disable_cognito_users.py`**: Desactiva todos los usuarios (requiere confirmación)
- **`delete_cognito_users.py`**: Elimina permanentemente todos los usuarios (requiere confirmación)

### Pruebas

- **`test_cognito_user_interactive.py`**: Test interactivo para registro y confirmación de usuarios
- **`test_cognito_user_demo.py`**: Demo automático del flujo de registro
- **`test_cognito_final.py`**: Test básico de login con usuario existente

## Configuración

Todos los scripts requieren un archivo `.env` en `/workspace_python-helpers/custom_cognito/.env` con las siguientes variables:

```bash
AWS_REGION=eu-west-1
AWS_PROFILE=your-profile  # Opcional
COGNITO_USER_POOL_ID=your-user-pool-id
COGNITO_APP_CLIENT_ID=your-app-client-id
COGNITO_APP_CLIENT_SECRET=your-secret  # Si aplica
```

## Uso

```bash
# Desde el directorio tools/cognito
python list_cognito_users.py
python test_cognito_user_interactive.py

# Desde el directorio raíz del proyecto
python tools/cognito/list_cognito_users.py
```

## Advertencias

⚠️ **CUIDADO**: Los scripts de eliminación y desactivación afectan a TODOS los usuarios del User Pool. Úsalos solo en entornos de desarrollo.

⚠️ **Límites de AWS**: AWS Cognito tiene límites diarios de emails. Si encuentras errores de límite, espera hasta el siguiente día.