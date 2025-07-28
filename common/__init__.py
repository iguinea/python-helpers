"""
Common utilities - Utilidades comunes para proyectos Python

Proporciona funciones helper para operaciones comunes como logging,
manejo de errores, validación, y más.
"""

from .logging import setup_logger, get_logger
from .errors import BaseError, ValidationError, ConfigurationError
from .validation import validate_email, validate_url, validate_json_schema

__all__ = [
    "setup_logger",
    "get_logger", 
    "BaseError",
    "ValidationError",
    "ConfigurationError",
    "validate_email",
    "validate_url",
    "validate_json_schema"
]