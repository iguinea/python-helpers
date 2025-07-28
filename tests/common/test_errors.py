"""
Tests para el módulo common.errors
"""

import pytest
from unittest.mock import MagicMock, patch

from common.errors import (
    BaseError,
    ValidationError,
    ConfigurationError,
    RetryableError,
    ErrorHandler,
    safe_execute
)


class TestBaseError:
    """Tests para BaseError"""
    
    @pytest.mark.unit
    def test_base_error_initialization(self):
        """Test inicialización básica de BaseError."""
        error = BaseError("Test error message")
        
        assert str(error) == "BaseError: Test error message"
        assert error.message == "Test error message"
        assert error.error_code == "BaseError"
        assert error.details == {}
        assert error.cause is None
        assert error.traceback is None
    
    @pytest.mark.unit
    def test_base_error_with_all_params(self):
        """Test BaseError con todos los parámetros."""
        cause = ValueError("Original error")
        error = BaseError(
            message="Custom error",
            error_code="CUSTOM_CODE",
            details={"field": "value", "count": 42},
            cause=cause
        )
        
        assert error.message == "Custom error"
        assert error.error_code == "CUSTOM_CODE"
        assert error.details == {"field": "value", "count": 42}
        assert error.cause == cause
        assert error.traceback is not None
    
    @pytest.mark.unit
    def test_base_error_to_dict(self):
        """Test conversión a diccionario."""
        error = BaseError(
            message="Test error",
            error_code="TEST_001",
            details={"key": "value"}
        )
        
        result = error.to_dict()
        
        assert result == {
            "error": "TEST_001",
            "message": "Test error",
            "details": {"key": "value"}
        }
    
    @pytest.mark.unit
    def test_base_error_to_dict_with_cause(self):
        """Test to_dict con causa."""
        cause = RuntimeError("Root cause")
        error = BaseError("Wrapped error", cause=cause)
        
        result = error.to_dict()
        
        assert result["cause"] == "Root cause"
    
    @pytest.mark.unit
    def test_base_error_str_representation(self):
        """Test representación string completa."""
        cause = Exception("Root cause")
        error = BaseError(
            message="Main error",
            error_code="ERR_001",
            details={"info": "additional"},
            cause=cause
        )
        
        str_repr = str(error)
        
        assert "ERR_001: Main error" in str_repr
        assert "Details: {'info': 'additional'}" in str_repr
        assert "Caused by: Root cause" in str_repr


class TestValidationError:
    """Tests para ValidationError"""
    
    @pytest.mark.unit
    def test_validation_error_basic(self):
        """Test ValidationError básico."""
        error = ValidationError("Invalid input")
        
        assert error.message == "Invalid input"
        assert error.error_code == "VALIDATION_ERROR"
        assert error.details == {}
    
    @pytest.mark.unit
    def test_validation_error_with_field(self):
        """Test ValidationError con campo."""
        error = ValidationError(
            "Invalid email format",
            field="email",
            value="not-an-email"
        )
        
        assert error.details["field"] == "email"
        assert error.details["value"] == "not-an-email"
    
    @pytest.mark.unit
    def test_validation_error_with_extra_details(self):
        """Test ValidationError con detalles adicionales."""
        error = ValidationError(
            "Value out of range",
            field="age",
            value=200,
            details={"min": 0, "max": 150}
        )
        
        assert error.details == {
            "field": "age",
            "value": 200,
            "min": 0,
            "max": 150
        }


class TestConfigurationError:
    """Tests para ConfigurationError"""
    
    @pytest.mark.unit
    def test_configuration_error(self):
        """Test ConfigurationError."""
        error = ConfigurationError(
            "Missing environment variable",
            details={"variable": "API_KEY", "required": True}
        )
        
        assert error.message == "Missing environment variable"
        assert error.error_code == "CONFIGURATION_ERROR"
        assert error.details["variable"] == "API_KEY"


class TestRetryableError:
    """Tests para RetryableError"""
    
    @pytest.mark.unit
    def test_retryable_error_basic(self):
        """Test RetryableError básico."""
        error = RetryableError("Temporary failure")
        
        assert error.message == "Temporary failure"
        assert error.error_code == "RETRYABLE_ERROR"
        assert error.retry_after is None
        assert error.max_retries is None
    
    @pytest.mark.unit
    def test_retryable_error_with_retry_params(self):
        """Test RetryableError con parámetros de reintento."""
        error = RetryableError(
            "Rate limit exceeded",
            retry_after=60,
            max_retries=3
        )
        
        assert error.retry_after == 60
        assert error.max_retries == 3
        assert error.details["retry_after"] == 60
        assert error.details["max_retries"] == 3


class TestErrorHandler:
    """Tests para ErrorHandler"""
    
    @pytest.mark.unit
    def test_error_handler_initialization(self):
        """Test inicialización de ErrorHandler."""
        handler = ErrorHandler()
        assert handler.logger is None
        assert handler.error_handlers == {}
    
    @pytest.mark.unit
    def test_error_handler_with_logger(self):
        """Test ErrorHandler con logger."""
        mock_logger = MagicMock()
        handler = ErrorHandler(logger=mock_logger)
        
        assert handler.logger == mock_logger
    
    @pytest.mark.unit
    def test_register_handler(self):
        """Test registro de manejador personalizado."""
        handler = ErrorHandler()
        custom_handler = MagicMock()
        
        handler.register_handler(ValueError, custom_handler)
        
        assert handler.error_handlers[ValueError] == custom_handler
    
    @pytest.mark.unit
    def test_handle_error_basic(self):
        """Test manejo básico de error."""
        handler = ErrorHandler()
        error = ValueError("Test error")
        
        with pytest.raises(ValueError):
            handler.handle_error(error)
    
    @pytest.mark.unit
    def test_handle_error_no_reraise(self):
        """Test manejo sin relanzar error."""
        handler = ErrorHandler()
        error = RuntimeError("Test error")
        
        result = handler.handle_error(error, reraise=False)
        
        assert result["type"] == "RuntimeError"
        assert result["message"] == "Test error"
        assert result["context"] == {}
    
    @pytest.mark.unit
    def test_handle_error_with_context(self):
        """Test manejo con contexto."""
        handler = ErrorHandler()
        error = Exception("Test")
        context = {"user_id": "123", "action": "update"}
        
        result = handler.handle_error(error, context=context, reraise=False)
        
        assert result["context"] == context
    
    @pytest.mark.unit
    def test_handle_base_error(self):
        """Test manejo de BaseError."""
        handler = ErrorHandler()
        error = BaseError(
            "Custom error",
            error_code="CUSTOM",
            details={"info": "test"}
        )
        
        result = handler.handle_error(error, reraise=False)
        
        assert result["error"] == "CUSTOM"
        assert result["message"] == "Custom error"
        assert result["details"]["info"] == "test"
    
    @pytest.mark.unit
    def test_handle_error_with_logger(self):
        """Test manejo con logging."""
        mock_logger = MagicMock()
        handler = ErrorHandler(logger=mock_logger)
        error = ValueError("Test")
        
        handler.handle_error(error, reraise=False)
        
        mock_logger.error.assert_called_once()
        call_args = mock_logger.error.call_args
        assert "Error handled: ValueError" in call_args[0][0]
    
    @pytest.mark.unit
    def test_handle_error_with_custom_handler(self):
        """Test manejo con manejador personalizado."""
        handler = ErrorHandler()
        custom_handler = MagicMock()
        handler.register_handler(ValueError, custom_handler)
        
        error = ValueError("Test")
        context = {"test": True}
        
        handler.handle_error(error, context=context, reraise=False)
        
        custom_handler.assert_called_once_with(error, context)


class TestSafeExecute:
    """Tests para safe_execute"""
    
    @pytest.mark.unit
    def test_safe_execute_success(self):
        """Test ejecución exitosa."""
        def test_func(x, y):
            return x + y
        
        result = safe_execute(test_func, x=5, y=3)
        assert result == 8
    
    @pytest.mark.unit
    def test_safe_execute_with_exception(self):
        """Test con excepción."""
        def failing_func():
            raise ValueError("Test error")
        
        result = safe_execute(failing_func, default="default_value")
        assert result == "default_value"
    
    @pytest.mark.unit
    def test_safe_execute_with_logger(self):
        """Test con logger."""
        mock_logger = MagicMock()
        
        def failing_func():
            raise RuntimeError("Test error")
        
        result = safe_execute(
            failing_func,
            default=None,
            logger=mock_logger
        )
        
        assert result is None
        mock_logger.error.assert_called_once()
        assert "Error in safe_execute" in mock_logger.error.call_args[0][0]
    
    @pytest.mark.unit
    def test_safe_execute_with_kwargs(self):
        """Test con argumentos kwargs."""
        def test_func(name, age=None):
            if age is None:
                raise ValueError("Age required")
            return f"{name} is {age} years old"
        
        # Sin age, debe fallar y retornar default
        result = safe_execute(
            test_func,
            default="Unknown",
            name="John"
        )
        assert result == "Unknown"
        
        # Con age, debe funcionar
        result = safe_execute(
            test_func,
            default="Unknown",
            name="John",
            age=30
        )
        assert result == "John is 30 years old"