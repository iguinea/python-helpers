"""
Error handling utilities - Clases base para manejo de errores

Proporciona clases de error base y utilidades para manejo consistente de errores.
"""

from typing import Optional, Dict, Any, List
import traceback
import sys


class BaseError(Exception):
    """
    Clase base para todos los errores personalizados de la aplicación.
    
    Attributes:
        message: Mensaje de error
        error_code: Código único del error
        details: Detalles adicionales del error
        cause: Excepción original que causó este error
    """
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        self.cause = cause
        self.traceback = traceback.format_exc() if cause else None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte el error a un diccionario para serialización."""
        result = {
            "error": self.error_code,
            "message": self.message,
            "details": self.details
        }
        
        if self.cause:
            result["cause"] = str(self.cause)
            
        return result
    
    def __str__(self) -> str:
        parts = [f"{self.error_code}: {self.message}"]
        
        if self.details:
            parts.append(f"Details: {self.details}")
            
        if self.cause:
            parts.append(f"Caused by: {self.cause}")
            
        return " | ".join(parts)


class ValidationError(BaseError):
    """
    Error de validación de datos.
    
    Example:
        >>> raise ValidationError(
        ...     "Formato de email inválido",
        ...     details={"field": "email", "value": "invalid-email"}
        ... )
    """
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Any = None,
        **kwargs
    ):
        details = kwargs.get("details", {})
        
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = value
            
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            details=details,
            **{k: v for k, v in kwargs.items() if k != "details"}
        )


class ConfigurationError(BaseError):
    """
    Error de configuración del sistema.
    
    Example:
        >>> raise ConfigurationError(
        ...     "Variable de entorno no encontrada",
        ...     details={"variable": "API_KEY", "required": True}
        ... )
    """
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message=message,
            error_code="CONFIGURATION_ERROR",
            **kwargs
        )


class RetryableError(BaseError):
    """
    Error que indica que la operación puede ser reintentada.
    
    Attributes:
        retry_after: Segundos a esperar antes de reintentar
        max_retries: Número máximo de reintentos permitidos
    """
    
    def __init__(
        self,
        message: str,
        retry_after: Optional[int] = None,
        max_retries: Optional[int] = None,
        **kwargs
    ):
        details = kwargs.get("details", {})
        
        if retry_after is not None:
            details["retry_after"] = retry_after
        if max_retries is not None:
            details["max_retries"] = max_retries
            
        super().__init__(
            message=message,
            error_code="RETRYABLE_ERROR",
            details=details,
            **{k: v for k, v in kwargs.items() if k != "details"}
        )
        
        self.retry_after = retry_after
        self.max_retries = max_retries


class ErrorHandler:
    """
    Manejador centralizado de errores con logging y formateo.
    
    Example:
        >>> handler = ErrorHandler(logger)
        >>> try:
        ...     risky_operation()
        ... except Exception as e:
        ...     handler.handle_error(e, context={"user_id": "123"})
    """
    
    def __init__(self, logger=None):
        self.logger = logger
        self.error_handlers = {}
    
    def register_handler(self, error_type: type, handler_func):
        """Registra un manejador personalizado para un tipo de error."""
        self.error_handlers[error_type] = handler_func
    
    def handle_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
        reraise: bool = True
    ) -> Optional[Dict[str, Any]]:
        """
        Maneja un error de forma consistente.
        
        Args:
            error: La excepción a manejar
            context: Contexto adicional del error
            reraise: Si se debe relanzar el error después de manejarlo
            
        Returns:
            Dict con información del error si no se relanza
        """
        error_info = {
            "type": type(error).__name__,
            "message": str(error),
            "context": context or {}
        }
        
        # Si es un BaseError, usar su método to_dict
        if isinstance(error, BaseError):
            error_info.update(error.to_dict())
        
        # Log del error si hay logger
        if self.logger:
            self.logger.error(
                f"Error handled: {error_info['type']}",
                extra={"error_info": error_info},
                exc_info=True
            )
        
        # Ejecutar manejador personalizado si existe
        handler = self.error_handlers.get(type(error))
        if handler:
            handler(error, context)
        
        if reraise:
            raise error
            
        return error_info


def safe_execute(func, default=None, logger=None, **kwargs):
    """
    Ejecuta una función de forma segura, capturando errores.
    
    Args:
        func: Función a ejecutar
        default: Valor por defecto si falla
        logger: Logger opcional para registrar errores
        **kwargs: Argumentos para la función
        
    Returns:
        Resultado de la función o valor por defecto
        
    Example:
        >>> result = safe_execute(
        ...     risky_function,
        ...     default={},
        ...     logger=logger,
        ...     param1="value1"
        ... )
    """
    try:
        return func(**kwargs)
    except Exception as e:
        if logger:
            logger.error(f"Error in safe_execute: {e}", exc_info=True)
        return default