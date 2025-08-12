"""
Python Helpers - Colección de utilidades reutilizables

Este paquete proporciona utilidades comunes para proyectos Python,
incluyendo autenticación, manejo de secretos AWS, y más.
"""

__version__ = "0.1.7"
__author__ = "Iñaki Guinea <iguinea@gmail.com>"

try:
    from . import custom_auth
    from . import custom_aws
    from . import custom_cognito

    __all__ = ["custom_auth", "custom_aws", "custom_cognito"]
except ImportError:
    # When running tests, imports might fail
    __all__ = []
