#!/usr/bin/env python3
"""
Test final del ciclo de vida de usuario en Cognito
Solo para verificar que todo funciona correctamente
"""
import asyncio
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


async def main():
    """Test básico de login con usuario existente"""
    print("=" * 80)
    print("TEST FINAL: VERIFICANDO LOGIN COGNITO")
    print("=" * 80)
    
    # Configuración
    settings = Settings()
    cognito_service = CognitoService(settings)
    
    # Datos de prueba
    email = "test_user@example.com"  # Usuario de prueba ya confirmado
    password = "TestPass123!"
    
    print(f"\nIntentando login con usuario de prueba...")
    print(f"Email: {email}")
    
    try:
        # Intentar login
        result = await cognito_service.login(email, password)
        print("\n✓ Login exitoso!")
        print(f"Access Token: {result['access_token'][:50]}...")
        print(f"ID Token: {result['id_token'][:50]}...")
        print(f"Refresh Token: {result['refresh_token'][:50]}...")
        print(f"Expires In: {result['expires_in']} seconds")
        
    except ValueError as e:
        print(f"\n✗ Error de validación: {e}")
    except Exception as e:
        print(f"\n✗ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    
    print(f"\n{'='*80}")
    print("TEST COMPLETADO")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    asyncio.run(main())