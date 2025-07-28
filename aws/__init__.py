"""
AWS module - Utilidades para servicios AWS

Proporciona funciones helper para trabajar con servicios AWS como Secrets Manager.
"""

from .secrets import get_secret_fields, parse_secret_json, test_secrets_manager_connection

__all__ = ["get_secret_fields", "parse_secret_json", "test_secrets_manager_connection"]