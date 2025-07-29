"""
Python Helpers - Colección de utilidades reutilizables

Este paquete proporciona utilidades comunes para proyectos Python,
incluyendo autenticación, manejo de secretos AWS, y más.
"""

__version__ = "0.1.4"
__author__ = "Iñaki Guinea <iguinea@gmail.com>"

from . import custom_auth
from . import custom_aws

__all__ = ["custom_auth", "custom_aws"]
