"""
Test de ciclo de vida completo de usuario en Cognito:
- Registrar usuario con email dinámico
- Esperar confirmación manual
- Desactivar y eliminar usuario
"""
import pytest
import asyncio
import time
import random
import string
from datetime import datetime
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar variables de entorno
env_path = Path(__file__).parent.parent.parent / "custom_cognito" / ".env"
load_dotenv(env_path)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from custom_cognito.cognito_service import CognitoService
from custom_cognito.config import Settings
from custom_cognito.schemas import UserRegister


def generate_random_suffix(length=8):
    """Genera un sufijo aleatorio para el email"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


@pytest.mark.integration_real
class TestUserLifecycle:
    """Test del ciclo de vida completo de un usuario real en Cognito"""
    
    @pytest.fixture
    def settings(self):
        """Configuración para las pruebas"""
        return Settings()
    
    @pytest.fixture
    def cognito_service(self, settings):
        """Instancia del servicio de Cognito"""
        return CognitoService(settings)
    
    @pytest.mark.asyncio
    async def test_user_registration_confirmation_and_deletion(self, cognito_service, settings):
        """
        Test completo del ciclo de vida del usuario:
        1. Registro con email dinámico
        2. Espera de confirmación manual
        3. Desactivación y eliminación
        """
        # Generar email dinámico
        random_suffix = generate_random_suffix()
        email = f"iguinea+pytest{random_suffix}@gmail.com"
        print(f"\n{'='*80}")
        print(f"TEST DE CICLO DE VIDA DE USUARIO EN COGNITO")
        print(f"{'='*80}")
        print(f"Email generado: {email}")
        
        # Datos del usuario
        user_data = UserRegister(
            email=email,
            password="SecureTestPass123!",
            full_name="Test User PyTest"
        )
        
        # 1. REGISTRAR USUARIO
        print(f"\n1. Registrando usuario...")
        try:
            result = await cognito_service.register_user(user_data)
            username = result['username']
            print(f"   ✓ Usuario registrado exitosamente")
            print(f"   - Username: {username}")
            print(f"   - UserSub: {result['user_sub']}")
            print(f"   - Confirmación requerida: {result['confirmation_required']}")
        except Exception as e:
            pytest.fail(f"Error al registrar usuario: {e}")
        
        # 2. ESPERAR CONFIRMACIÓN
        print(f"\n2. Esperando confirmación del email...")
        print(f"   ⚠️  Por favor, confirma el email {email}")
        print(f"   Esperaré hasta 10 intentos (10 segundos entre cada intento)")
        print(f"   También puedes ingresar el código de confirmación manualmente.")
        
        confirmed = False
        for attempt in range(1, 11):
            print(f"\n   Intento {attempt}/10...")
            
            # Preguntar si quiere ingresar el código manualmente
            print(f"   ¿Tienes el código de confirmación? (Enter para saltar, o ingresa el código de 6 dígitos): ", end='', flush=True)
            
            # Esperar entrada con timeout usando select (para Linux/Unix)
            import select
            ready, _, _ = select.select([sys.stdin], [], [], 2.0)  # 2 segundos de timeout
            
            if ready:
                code = sys.stdin.readline().strip()
                if code and len(code) == 6 and code.isdigit():
                    # Intentar confirmar con el código
                    try:
                        print(f"   Confirmando con código: {code}")
                        await cognito_service.confirm_email(email, code)
                        print(f"   ✓ Email confirmado exitosamente!")
                        
                        # Ahora intentar login
                        await cognito_service.login(email, user_data.password)
                        confirmed = True
                        print(f"   ✓ Login exitoso después de confirmación!")
                        break
                    except ValueError as e:
                        print(f"   ✗ Error al confirmar: {e}")
                    except Exception as e:
                        print(f"   ✗ Error inesperado: {e}")
            
            # Verificar si el usuario está confirmado (intentando login)
            try:
                await cognito_service.login(email, user_data.password)
                confirmed = True
                print(f"   ✓ Usuario confirmado exitosamente!")
                break
            except ValueError as e:
                if "Email not verified" in str(e):
                    print(f"   - Email aún no verificado")
                else:
                    print(f"   - Error: {e}")
            except Exception as e:
                print(f"   - Error inesperado: {e}")
            
            if attempt < 10:
                print(f"   Esperando 8 segundos antes del siguiente intento...")
                await asyncio.sleep(8)
        
        if not confirmed:
            print(f"\n   ✗ El usuario no fue confirmado después de 10 intentos")
            print(f"   Procediendo con la limpieza de todos modos...")
        
        # 3. DESACTIVAR USUARIO
        print(f"\n3. Desactivando usuario...")
        try:
            cognito_service.client.admin_disable_user(
                UserPoolId=settings.cognito_user_pool_id,
                Username=username
            )
            print(f"   ✓ Usuario desactivado exitosamente")
        except Exception as e:
            print(f"   ✗ Error al desactivar usuario: {e}")
        
        # 4. ELIMINAR USUARIO
        print(f"\n4. Eliminando usuario...")
        try:
            cognito_service.client.admin_delete_user(
                UserPoolId=settings.cognito_user_pool_id,
                Username=username
            )
            print(f"   ✓ Usuario eliminado exitosamente")
        except Exception as e:
            print(f"   ✗ Error al eliminar usuario: {e}")
            pytest.fail(f"No se pudo eliminar el usuario: {e}")
        
        print(f"\n{'='*80}")
        print(f"TEST COMPLETADO")
        print(f"{'='*80}\n")


if __name__ == "__main__":
    # Ejecutar el test directamente
    pytest.main([__file__, "-v", "-s", "-m", "integration_real"])