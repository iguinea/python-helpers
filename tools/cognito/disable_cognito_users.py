#!/usr/bin/env python3
"""
Script para desactivar todos los usuarios de Cognito
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError

# Cargar las variables de entorno desde el archivo .env
env_path = Path(__file__).parent.parent.parent / "custom_cognito" / ".env"
print(f">env_path: {env_path}")
loaded = load_dotenv(env_path)
if not loaded:
    print(f"No se pudo cargar el archivo .env en {env_path}")
    sys.exit(1)


def disable_all_cognito_users():
    """Desactiva todos los usuarios del User Pool de Cognito"""

    # Configuración
    aws_region = os.getenv("AWS_REGION", "eu-west-1")
    aws_profile = os.getenv("AWS_PROFILE")
    user_pool_id = os.getenv("COGNITO_USER_POOL_ID")

    if not user_pool_id:
        print("Error: COGNITO_USER_POOL_ID no está configurado")
        return

    # Configurar cliente boto3
    try:
        if aws_profile:
            session = boto3.Session(profile_name=aws_profile)
            client = session.client("cognito-idp", region_name=aws_region)
        else:
            client = boto3.client("cognito-idp", region_name=aws_region)
    except Exception as e:
        print(f"Error al configurar el cliente de AWS: {e}")
        return

    print(f"Desactivando usuarios del User Pool: {user_pool_id}")
    print(f"Región: {aws_region}")
    print(f"Perfil AWS: {aws_profile or 'credenciales por defecto'}")
    print("-" * 80)

    try:
        pagination_token = None
        total_users = 0
        disabled_users = 0
        errors = 0

        while True:
            # Construir parámetros de la petición
            params = {
                "UserPoolId": user_pool_id,
                "Limit": 60,  # Máximo permitido por AWS
            }

            if pagination_token:
                params["PaginationToken"] = pagination_token

            # Hacer la petición para listar usuarios
            response = client.list_users(**params)

            # Procesar usuarios
            for user in response["Users"]:
                total_users += 1
                username = user["Username"]
                status = user["UserStatus"]

                # Extraer email
                attributes = {}
                for attr in user.get("Attributes", []):
                    attributes[attr["Name"]] = attr["Value"]
                email = attributes.get("email", "N/A")

                # Si el usuario ya está desactivado, saltar
                if status == "DISABLED":
                    print(
                        f"Usuario {username} ({email}) ya está desactivado - Saltando"
                    )
                    continue

                # Intentar desactivar el usuario
                try:
                    client.admin_disable_user(
                        UserPoolId=user_pool_id, Username=username
                    )
                    disabled_users += 1
                    print(f"✓ Usuario desactivado: {username} ({email})")

                except ClientError as e:
                    errors += 1
                    error_code = e.response["Error"]["Code"]
                    error_message = e.response["Error"]["Message"]
                    print(
                        f"✗ Error al desactivar {username} ({email}): {error_code} - {error_message}"
                    )

                except Exception as e:
                    errors += 1
                    print(f"✗ Error inesperado al desactivar {username} ({email}): {e}")

            # Verificar si hay más páginas
            pagination_token = response.get("PaginationToken")
            if not pagination_token:
                break

        print("\n" + "-" * 80)
        print(f"Resumen:")
        print(f"  Total de usuarios procesados: {total_users}")
        print(f"  Usuarios desactivados exitosamente: {disabled_users}")
        print(f"  Errores encontrados: {errors}")

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        print(f"\nError al listar usuarios:")
        print(f"  Código: {error_code}")
        print(f"  Mensaje: {error_message}")

        if error_code == "ResourceNotFoundException":
            print("  El User Pool especificado no existe")
        elif error_code == "AccessDeniedException":
            print("  No tienes permisos para administrar usuarios en este User Pool")

    except Exception as e:
        print(f"\nError inesperado: {e}")


if __name__ == "__main__":
    # Confirmar antes de proceder
    print(
        "ADVERTENCIA: Este script desactivará TODOS los usuarios del User Pool de Cognito."
    )
    print("Los usuarios desactivados no podrán iniciar sesión.")
    response = input(
        "\n¿Estás seguro de que deseas continuar? (escribe 'SI' para confirmar): "
    )

    if response.upper() == "SI":
        print("\nProcediendo con la desactivación...\n")
        disable_all_cognito_users()
    else:
        print("\nOperación cancelada.")
