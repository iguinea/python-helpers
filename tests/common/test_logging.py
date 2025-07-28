"""
Tests para el módulo common.logging
"""

import logging
import os
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from common.logging import setup_logger, get_logger, ContextLogger


class TestSetupLogger:
    """Tests para setup_logger"""
    
    @pytest.mark.unit
    def test_setup_logger_basic(self):
        """Test configuración básica de logger."""
        logger = setup_logger("test_app")
        
        assert logger.name == "test_app"
        assert logger.level == logging.INFO
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)
        assert not logger.propagate
    
    @pytest.mark.unit
    def test_setup_logger_with_level(self):
        """Test configuración con nivel personalizado."""
        logger = setup_logger("test_debug", level="DEBUG")
        assert logger.level == logging.DEBUG
        
        logger = setup_logger("test_error", level="ERROR")
        assert logger.level == logging.ERROR
    
    @pytest.mark.unit
    def test_setup_logger_with_file(self, temp_log_file):
        """Test configuración con archivo de log."""
        logger = setup_logger("test_file", log_file=temp_log_file)
        
        # Debe tener 2 handlers: console y archivo
        assert len(logger.handlers) == 2
        
        # Verificar tipos de handlers
        handler_types = [type(h) for h in logger.handlers]
        assert logging.StreamHandler in handler_types
        assert logging.FileHandler in handler_types
        
        # Verificar que el archivo se crea
        assert os.path.exists(temp_log_file)
    
    @pytest.mark.unit
    def test_setup_logger_creates_parent_dirs(self, temp_dir):
        """Test que crea directorios padre si no existen."""
        log_path = os.path.join(temp_dir, "logs", "subdir", "app.log")
        logger = setup_logger("test_dirs", log_file=log_path)
        
        assert os.path.exists(os.path.dirname(log_path))
    
    @pytest.mark.unit
    def test_setup_logger_custom_format(self):
        """Test con formato personalizado."""
        custom_format = "%(levelname)s - %(message)s"
        logger = setup_logger("test_format", format_string=custom_format)
        
        # Verificar formato del handler
        formatter = logger.handlers[0].formatter
        assert formatter._fmt == custom_format
    
    @pytest.mark.unit
    def test_setup_logger_clears_existing_handlers(self):
        """Test que limpia handlers existentes."""
        # Crear logger con handler inicial
        logger = logging.getLogger("test_clear")
        initial_handler = logging.NullHandler()
        logger.addHandler(initial_handler)
        
        # Setup debe limpiar handlers existentes
        setup_logger("test_clear")
        
        assert initial_handler not in logger.handlers
        assert len(logger.handlers) == 1
    
    @pytest.mark.unit
    def test_setup_logger_case_insensitive_level(self):
        """Test que el nivel es case-insensitive."""
        logger1 = setup_logger("test1", level="debug")
        logger2 = setup_logger("test2", level="DEBUG")
        logger3 = setup_logger("test3", level="DeBuG")
        
        assert logger1.level == logging.DEBUG
        assert logger2.level == logging.DEBUG
        assert logger3.level == logging.DEBUG


class TestGetLogger:
    """Tests para get_logger"""
    
    @pytest.mark.unit
    def test_get_logger_new(self):
        """Test obtener un logger nuevo."""
        logger_name = "test.module.new"
        logger = get_logger(logger_name)
        
        assert logger.name == logger_name
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)
        assert logger.level == logging.INFO
    
    @pytest.mark.unit
    def test_get_logger_existing(self):
        """Test obtener un logger existente."""
        # Crear logger primero
        logger_name = "test.existing"
        logger1 = get_logger(logger_name)
        
        # Agregar un handler adicional para verificar que no se reinicializa
        custom_handler = logging.NullHandler()
        logger1.addHandler(custom_handler)
        
        # Obtener el mismo logger
        logger2 = get_logger(logger_name)
        
        # Debe ser el mismo objeto
        assert logger1 is logger2
        # Debe mantener los handlers existentes
        assert custom_handler in logger2.handlers
    
    @pytest.mark.unit
    def test_get_logger_with_module_name(self):
        """Test usando __name__ como nombre."""
        logger = get_logger(__name__)
        # El nombre puede variar dependiendo de cómo se ejecute el test
        assert logger.name == __name__


class TestContextLogger:
    """Tests para ContextLogger"""
    
    @pytest.fixture
    def base_logger(self):
        """Logger base para pruebas."""
        logger = logging.getLogger("test_context")
        logger.handlers.clear()
        
        # Agregar handler que captura mensajes
        handler = logging.StreamHandler()
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        
        return logger
    
    @pytest.mark.unit
    def test_context_logger_initialization(self, base_logger):
        """Test inicialización de ContextLogger."""
        context_logger = ContextLogger(base_logger, user_id="123", request_id="abc")
        
        assert context_logger.logger == base_logger
        assert context_logger.context == {"user_id": "123", "request_id": "abc"}
    
    @pytest.mark.unit
    def test_context_logger_format_message(self, base_logger):
        """Test formato de mensajes con contexto."""
        context_logger = ContextLogger(base_logger, user_id="123", action="login")
        
        formatted = context_logger._format_message("User logged in")
        assert formatted == "[user_id=123 action=login] User logged in"
    
    @pytest.mark.unit
    def test_context_logger_format_message_no_context(self, base_logger):
        """Test formato sin contexto."""
        context_logger = ContextLogger(base_logger)
        
        formatted = context_logger._format_message("Simple message")
        assert formatted == "Simple message"
    
    @pytest.mark.unit
    def test_context_logger_all_levels(self, base_logger):
        """Test todos los niveles de logging con contexto."""
        with patch.object(base_logger, 'debug') as mock_debug, \
             patch.object(base_logger, 'info') as mock_info, \
             patch.object(base_logger, 'warning') as mock_warning, \
             patch.object(base_logger, 'error') as mock_error, \
             patch.object(base_logger, 'critical') as mock_critical:
            
            context_logger = ContextLogger(base_logger, session="xyz")
            
            # Probar cada nivel
            context_logger.debug("Debug message")
            mock_debug.assert_called_with("[session=xyz] Debug message")
            
            context_logger.info("Info message")
            mock_info.assert_called_with("[session=xyz] Info message")
            
            context_logger.warning("Warning message")
            mock_warning.assert_called_with("[session=xyz] Warning message")
            
            context_logger.error("Error message")
            mock_error.assert_called_with("[session=xyz] Error message")
            
            context_logger.critical("Critical message")
            mock_critical.assert_called_with("[session=xyz] Critical message")
    
    @pytest.mark.unit
    def test_context_logger_exception(self, base_logger):
        """Test logging de excepciones con contexto."""
        with patch.object(base_logger, 'exception') as mock_exception:
            context_logger = ContextLogger(base_logger, error_id="err123")
            
            context_logger.exception("Exception occurred")
            mock_exception.assert_called_with("[error_id=err123] Exception occurred")
    
    @pytest.mark.unit
    def test_context_logger_multiple_contexts(self, base_logger):
        """Test con múltiples valores de contexto."""
        context_logger = ContextLogger(
            base_logger,
            user_id="123",
            session_id="abc",
            ip="192.168.1.1"
        )
        
        formatted = context_logger._format_message("Request processed")
        assert "[user_id=123 session_id=abc ip=192.168.1.1]" in formatted
        assert "Request processed" in formatted
    
    @pytest.mark.unit
    def test_context_logger_preserves_args_kwargs(self, base_logger):
        """Test que preserva args y kwargs adicionales."""
        with patch.object(base_logger, 'info') as mock_info:
            context_logger = ContextLogger(base_logger, app="myapp")
            
            # Llamar con args y kwargs adicionales
            context_logger.info("User %s logged in", "john", extra={"ip": "10.0.0.1"})
            
            # Verificar que se pasaron correctamente
            mock_info.assert_called_with(
                "[app=myapp] User %s logged in",
                "john",
                extra={"ip": "10.0.0.1"}
            )
    
    @pytest.mark.integration
    def test_context_logger_real_output(self, caplog):
        """Test integración con salida real de logs."""
        logger = logging.getLogger("test_real_context")
        context_logger = ContextLogger(logger, user="admin", action="delete")
        
        with caplog.at_level(logging.INFO):
            context_logger.info("Deleted resource")
        
        assert "[user=admin action=delete] Deleted resource" in caplog.text