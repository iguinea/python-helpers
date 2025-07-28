"""
Logging utilities - Configuración y manejo de logs

Proporciona funciones para configurar y obtener loggers con formato consistente.
"""

import logging
import sys
from typing import Optional, Dict, Any
from pathlib import Path


def setup_logger(
    name: str = "app",
    level: str = "INFO",
    log_file: Optional[str] = None,
    format_string: Optional[str] = None,
    **kwargs
) -> logging.Logger:
    """
    Configura un logger con formato y handlers consistentes.
    
    Args:
        name: Nombre del logger
        level: Nivel de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path opcional para guardar logs en archivo
        format_string: Formato personalizado para los logs
        **kwargs: Argumentos adicionales para el formatter
        
    Returns:
        logging.Logger: Logger configurado
        
    Example:
        >>> logger = setup_logger("mi_app", level="DEBUG", log_file="app.log")
        >>> logger.info("Aplicación iniciada")
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Evitar duplicación de handlers
    if logger.handlers:
        logger.handlers.clear()
    
    # Formato por defecto
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    formatter = logging.Formatter(format_string, **kwargs)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler si se especifica
    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Evitar propagación a root logger
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Obtiene un logger existente o crea uno nuevo con configuración básica.
    
    Args:
        name: Nombre del logger (generalmente __name__)
        
    Returns:
        logging.Logger: Logger listo para usar
        
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.debug("Mensaje de debug")
    """
    logger = logging.getLogger(name)
    
    # Si no tiene handlers, configurar uno básico
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    return logger


class ContextLogger:
    """
    Logger que incluye contexto adicional en todos los mensajes.
    
    Example:
        >>> logger = ContextLogger(get_logger(__name__), user_id="123")
        >>> logger.info("Usuario autenticado")  # Incluirá user_id en el log
    """
    
    def __init__(self, logger: logging.Logger, **context):
        self.logger = logger
        self.context = context
    
    def _format_message(self, msg: str) -> str:
        """Agrega contexto al mensaje."""
        if self.context:
            context_str = " ".join(f"{k}={v}" for k, v in self.context.items())
            return f"[{context_str}] {msg}"
        return msg
    
    def debug(self, msg: str, *args, **kwargs):
        self.logger.debug(self._format_message(msg), *args, **kwargs)
    
    def info(self, msg: str, *args, **kwargs):
        self.logger.info(self._format_message(msg), *args, **kwargs)
    
    def warning(self, msg: str, *args, **kwargs):
        self.logger.warning(self._format_message(msg), *args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs):
        self.logger.error(self._format_message(msg), *args, **kwargs)
    
    def critical(self, msg: str, *args, **kwargs):
        self.logger.critical(self._format_message(msg), *args, **kwargs)
    
    def exception(self, msg: str, *args, **kwargs):
        self.logger.exception(self._format_message(msg), *args, **kwargs)