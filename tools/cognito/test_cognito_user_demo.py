#!/usr/bin/env python3
"""
Script de demostración del ciclo de vida de usuario en Cognito
Solo registra, muestra info y elimina - útil para verificar que las correcciones funcionan
"""
import asyncio
import random
import string
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar variables de entorno
env_path = Path(__file__).parent.parent.parent / "custom_cognito" / ".env"
print(f">env_path: {env_path}")
loaded = load_dotenv(env_path)
if not loaded:
    print(f"No se pudo cargar el archivo .env en {env_path}")
    sys.exit(1)

# sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# Add the workspace root to Python path so we can import custom_cognito
workspace_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(workspace_root))

from custom_cognito.cognito_service import CognitoService
from custom_cognito.config import Settings
from custom_cognito.schemas import UserRegister


def generate_random_suffix(length=8):
    """Genera un sufijo aleatorio para el email"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


async def main():
    """Función principal del test"""
    print("=" * 80)
    print("DEMO: REGISTRO Y LIMPIEZA DE USUARIO EN COGNITO")
    print("=" * 80)

    # Configuración
    settings = Settings()
    cognito_service = CognitoService(settings)

    # Generar email dinámico
    random_suffix = generate_random_suffix()
    email = f"iguinea+pytest{random_suffix}@gmail.com"
    print(f"\nEmail de prueba: {email}")

    # Datos del usuario
    user_data = UserRegister(
        email=email, password="SecureTestPass123!", full_name="Test User PyTest"
    )

    username = None

    try:
        # 1. REGISTRAR USUARIO
        print(f"\n1. Registrando usuario...")
        result = await cognito_service.register_user(user_data)
        username = result["username"]
        print(f"   ✓ Usuario registrado exitosamente")
        print(f"   - Username: {username}")
        print(f"   - UserSub: {result['user_sub']}")
        print(f"   - Email: {email}")
        print(f"   - Result: {result}")

        # 2. VERIFICAR QUE EL LOGIN FALLA SIN CONFIRMACIÓN
        print(f"\n2. Verificando que el login falla sin confirmación...")
        try:
            await cognito_service.login(email, user_data.password)
            print(f"   ✗ ERROR: El login no debería funcionar sin confirmación")
        except ValueError as e:
            if "Email not verified" in str(e):
                print(f"   ✓ Correcto: {e}")
            else:
                print(f"   ? Error inesperado: {e}")
        except Exception as e:
            print(f"   ? Error inesperado: {type(e).__name__}: {e}")

        # 3. SIMULAR CONFIRMACIÓN Y LOGIN (para verificar que el código funciona)
        print(f"\n3. Para probar el login completo:")
        print(f"   1. Ejecuta: python test_cognito_user_interactive.py")
        print(f"   2. O confirma manualmente el email: {email}")
        print(f"   3. Luego intenta hacer login con:")
        print(f"      - Email: {email}")
        print(f"      - Password: SecureTestPass123!")

    except Exception as e:
        print(f"\n✗ Error durante el registro: {type(e).__name__}: {e}")

    finally:
        # 4. LIMPIEZA
        if username:
            print(f"\n4. Limpiando usuario de prueba...")
            try:
                # Desactivar
                cognito_service.client.admin_disable_user(
                    UserPoolId=settings.cognito_user_pool_id, Username=username
                )
                print(f"   ✓ Usuario desactivado")

                # Eliminar
                cognito_service.client.admin_delete_user(
                    UserPoolId=settings.cognito_user_pool_id, Username=username
                )
                print(f"   ✓ Usuario eliminado")

            except Exception as e:
                print(f"   ✗ Error durante la limpieza: {e}")

    print(f"\n{'='*80}")
    print("DEMO COMPLETADA")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    asyncio.run(main())
