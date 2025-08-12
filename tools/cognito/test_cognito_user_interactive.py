#!/usr/bin/env python3
"""
Script interactivo para probar el ciclo de vida de un usuario en Cognito
Permite ingresar el código de confirmación manualmente
"""
import asyncio
import random
import string
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar variables de entorno
env_path = Path(__file__).parent / "custom_cognito" / ".env"
load_dotenv(env_path)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from custom_cognito.cognito_service import CognitoService
from custom_cognito.config import Settings
from custom_cognito.schemas import UserRegister


def generate_random_suffix(length=8):
    """Genera un sufijo aleatorio para el email"""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


async def main():
    """Función principal del test interactivo"""
    print("=" * 80)
    print("TEST INTERACTIVO DE USUARIO EN COGNITO")
    print("=" * 80)

    # Configuración
    settings = Settings()
    cognito_service = CognitoService(settings)

    # Generar email dinámico
    random_suffix = generate_random_suffix()
    email = f"iguinea+pytest{random_suffix}@gmail.com"
    print(f"\nEmail a registrar: {email}")

    # Datos del usuario
    user_data = UserRegister(
        email=email, password="SecureTestPass123!", full_name="Test User PyTest"
    )

    # 1. REGISTRAR USUARIO
    print(f"\n1. Registrando usuario...")
    try:
        result = await cognito_service.register_user(user_data)
        username = result["username"]
        print(f"   ✓ Usuario registrado exitosamente")
        print(f"   - Username: {username}")
        print(f"   - UserSub: {result['user_sub']}")
    except Exception as e:
        print(f"   ✗ Error al registrar usuario: {e}")
        return

    # 2. ESPERAR CONFIRMACIÓN
    print(f"\n2. Esperando confirmación del email...")
    print(f"   ⚠️  Por favor, revisa el email {email}")
    print(f"   Ingresa el código de 6 dígitos cuando lo recibas")

    confirmed = False
    max_attempts = 10
    code_used = set()  # Para rastrear códigos ya usados

    for attempt in range(1, max_attempts + 1):
        print(f"\n   Intento {attempt}/{max_attempts}")

        # Solicitar código
        code = input(
            "   Código de confirmación (6 dígitos, o Enter para reintentar): "
        ).strip()

        if code and len(code) == 6 and code.isdigit():
            # Verificar si el código ya fue usado
            if code in code_used:
                print(
                    f"   ⚠️  Este código ya fue usado. Si necesitas uno nuevo, solicítalo en tu email."
                )
                continue

            code_used.add(code)

            # Intentar confirmar con el código
            try:
                print(f"   Confirmando con código: {code}")
                await cognito_service.confirm_email(user_data.email, code)
                print(f"   ✓ Email confirmado exitosamente!")

                # Esperar un momento antes de intentar login
                await asyncio.sleep(1)

                # Verificar login
                print(f"   Verificando login....-...")
                await cognito_service.login(user_data.email, user_data.password)
                confirmed = True
                print(f"   ✓ Login exitoso!")
                break

            except ValueError as e:
                print(f"   ✗ Error: {e}")
                if "Invalid verification code" in str(e):
                    print("   Por favor, verifica el código e intenta nuevamente")
                elif "Verification code has expired" in str(e):
                    print("   El código ha expirado. Solicita uno nuevo.")
                elif "Email not verified" in str(e):
                    print(
                        "   El email aún no está verificado. Por favor intenta de nuevo."
                    )
            except Exception as e:
                print(f"   ✗ Error inesperado: {e}")
                print(f"   Detalle: {type(e).__name__}")
        else:
            # Verificar si ya está confirmado
            try:
                await cognito_service.login(email, user_data.password)
                confirmed = True
                print(f"   ✓ Usuario ya está confirmado!")
                break
            except ValueError as e:
                if "Email not verified" in str(e):
                    print(f"   - Email aún no verificado")
                else:
                    print(f"   - {e}")
            except Exception:
                pass

    if not confirmed:
        print(f"\n   ✗ No se pudo confirmar el usuario")
        print(f"   Procediendo con la limpieza...")

    # 3. DESACTIVAR Y ELIMINAR USUARIO
    print(f"\n3. Limpieza del usuario de prueba...")

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
    print("TEST COMPLETADO")
    if confirmed:
        print("✓ El usuario fue confirmado exitosamente")
    else:
        print("✗ El usuario no pudo ser confirmado")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    asyncio.run(main())
