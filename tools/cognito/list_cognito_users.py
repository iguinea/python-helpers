#!/usr/bin/env python3
"""
Script para listar todos los usuarios de Cognito
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import boto3
from botocore.exceptions import ClientError

# Cargar las variables de entorno desde el archivo .env
env_path = Path(__file__).parent / "custom_cognito" / ".env"
load_dotenv(env_path)

def list_cognito_users():
    """Lista todos los usuarios del User Pool de Cognito"""
    
    # Configuración
    aws_region = os.getenv('AWS_REGION', 'eu-west-1')
    aws_profile = os.getenv('AWS_PROFILE')
    user_pool_id = os.getenv('COGNITO_USER_POOL_ID')
    
    if not user_pool_id:
        print("Error: COGNITO_USER_POOL_ID no está configurado")
        return
    
    # Configurar cliente boto3
    try:
        if aws_profile:
            session = boto3.Session(profile_name=aws_profile)
            client = session.client('cognito-idp', region_name=aws_region)
        else:
            client = boto3.client('cognito-idp', region_name=aws_region)
    except Exception as e:
        print(f"Error al configurar el cliente de AWS: {e}")
        return
    
    print(f"Listando usuarios del User Pool: {user_pool_id}")
    print(f"Región: {aws_region}")
    print(f"Perfil AWS: {aws_profile or 'credenciales por defecto'}")
    print("-" * 80)
    
    try:
        pagination_token = None
        user_count = 0
        
        while True:
            # Construir parámetros de la petición
            params = {
                'UserPoolId': user_pool_id,
                'Limit': 60  # Máximo permitido por AWS
            }
            
            if pagination_token:
                params['PaginationToken'] = pagination_token
            
            # Hacer la petición
            response = client.list_users(**params)
            
            # Procesar usuarios
            for user in response['Users']:
                user_count += 1
                username = user['Username']
                status = user['UserStatus']
                created = user['UserCreateDate']
                modified = user['UserLastModifiedDate']
                
                # Extraer atributos
                attributes = {}
                for attr in user.get('Attributes', []):
                    attributes[attr['Name']] = attr['Value']
                
                email = attributes.get('email', 'N/A')
                name = attributes.get('name', 'N/A')
                email_verified = attributes.get('email_verified', 'false')
                
                print(f"\nUsuario #{user_count}:")
                print(f"  Username: {username}")
                print(f"  Email: {email}")
                print(f"  Nombre: {name}")
                print(f"  Estado: {status}")
                print(f"  Email verificado: {email_verified}")
                print(f"  Creado: {created}")
                print(f"  Modificado: {modified}")
                
                # Mostrar si tiene MFA habilitado
                mfa_options = user.get('MFAOptions', [])
                if mfa_options:
                    print(f"  MFA: Habilitado ({', '.join([opt['DeliveryMedium'] for opt in mfa_options])})")
                else:
                    print(f"  MFA: No habilitado")
            
            # Verificar si hay más páginas
            pagination_token = response.get('PaginationToken')
            if not pagination_token:
                break
        
        print("\n" + "-" * 80)
        print(f"Total de usuarios encontrados: {user_count}")
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"\nError al listar usuarios:")
        print(f"  Código: {error_code}")
        print(f"  Mensaje: {error_message}")
        
        if error_code == 'ResourceNotFoundException':
            print("  El User Pool especificado no existe")
        elif error_code == 'AccessDeniedException':
            print("  No tienes permisos para listar usuarios en este User Pool")
    
    except Exception as e:
        print(f"\nError inesperado: {e}")

if __name__ == "__main__":
    list_cognito_users()