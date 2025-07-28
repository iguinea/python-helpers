"""
Tests para el módulo common.validation
"""

import pytest
from common.validation import (
    validate_email,
    validate_url,
    validate_json_schema,
    validate_not_empty,
    validate_in_range
)
from common.errors import ValidationError


class TestValidateEmail:
    """Tests para validate_email"""
    
    @pytest.mark.unit
    @pytest.mark.parametrize("email", [
        "user@example.com",
        "john.doe@company.com",
        "test+tag@domain.co.uk",
        "admin123@sub.domain.org",
        "user_name@example-site.com",
    ])
    def test_valid_emails(self, email):
        """Test emails válidos."""
        result = validate_email(email)
        assert result == email.lower()
    
    @pytest.mark.unit
    @pytest.mark.parametrize("email", [
        "",
        None,
        "not-an-email",
        "@example.com",
        "user@",
        "user@.com",
        "user@domain",
        "user @example.com",
        "user@example .com",
        "user@@example.com",
    ])
    def test_invalid_emails(self, email):
        """Test emails inválidos."""
        with pytest.raises(ValidationError) as exc_info:
            validate_email(email)
        
        error = exc_info.value
        assert error.error_code == "VALIDATION_ERROR"
        if email:
            assert "Formato de email inválido" in error.message
    
    @pytest.mark.unit
    def test_email_normalization(self):
        """Test normalización de email."""
        # Espacios y mayúsculas
        result = validate_email("  User@EXAMPLE.COM  ")
        assert result == "user@example.com"
    
    @pytest.mark.unit
    def test_email_error_details(self):
        """Test detalles del error de email."""
        with pytest.raises(ValidationError) as exc_info:
            validate_email("invalid-email")
        
        error = exc_info.value
        assert error.details["field"] == "email"
        assert error.details["value"] == "invalid-email"
        assert "pattern" in error.details


class TestValidateUrl:
    """Tests para validate_url"""
    
    @pytest.mark.unit
    @pytest.mark.parametrize("url", [
        "http://example.com",
        "https://www.example.com",
        "https://subdomain.example.com/path",
        "http://example.com:8080",
        "https://example.com/path?query=value",
        "https://example.com/path#anchor",
    ])
    def test_valid_urls(self, url):
        """Test URLs válidas."""
        result = validate_url(url)
        assert result == url
    
    @pytest.mark.unit
    @pytest.mark.parametrize("url", [
        "",
        None,
        "not-a-url",
        "example.com",
        "//example.com",
        "http://",
        "https://",
        "ftp://example.com",  # esquema no permitido por defecto
    ])
    def test_invalid_urls(self, url):
        """Test URLs inválidas."""
        with pytest.raises(ValidationError):
            validate_url(url)
    
    @pytest.mark.unit
    def test_url_custom_schemes(self):
        """Test URLs con esquemas personalizados."""
        # FTP permitido
        result = validate_url("ftp://files.example.com", schemes=["ftp", "ftps"])
        assert result == "ftp://files.example.com"
        
        # HTTP no permitido
        with pytest.raises(ValidationError) as exc_info:
            validate_url("http://example.com", schemes=["https"])
        
        error = exc_info.value
        assert "Esquema URL no permitido" in error.message
        assert error.details["allowed_schemes"] == ["https"]
    
    @pytest.mark.unit
    def test_url_error_details(self):
        """Test detalles del error de URL."""
        with pytest.raises(ValidationError) as exc_info:
            validate_url("example.com")
        
        error = exc_info.value
        assert error.details["field"] == "url"
        assert error.details["value"] == "example.com"


class TestValidateJsonSchema:
    """Tests para validate_json_schema"""
    
    @pytest.fixture
    def simple_schema(self):
        """Esquema simple para pruebas."""
        return {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer", "minimum": 0}
            }
        }
    
    @pytest.mark.unit
    def test_valid_data_simple_schema(self, simple_schema):
        """Test datos válidos contra esquema simple."""
        data = {"name": "John", "age": 30}
        result = validate_json_schema(data, simple_schema)
        assert result == data
    
    @pytest.mark.unit
    def test_missing_required_field(self, simple_schema):
        """Test campo requerido faltante."""
        data = {"age": 30}
        
        with pytest.raises(ValidationError) as exc_info:
            validate_json_schema(data, simple_schema)
        
        assert "Campos requeridos faltantes" in exc_info.value.message
        assert "name" in exc_info.value.details["missing_fields"]
    
    @pytest.mark.unit
    def test_wrong_type(self, simple_schema):
        """Test tipo incorrecto."""
        data = {"name": 123, "age": 30}
        
        with pytest.raises(ValidationError) as exc_info:
            validate_json_schema(data, simple_schema)
        
        assert "Tipo incorrecto" in exc_info.value.message
        assert exc_info.value.details["field"] == "name"
    
    @pytest.mark.unit
    def test_string_validations(self):
        """Test validaciones de string."""
        schema = {
            "type": "object",
            "properties": {
                "short": {"type": "string", "minLength": 3, "maxLength": 10},
                "pattern": {"type": "string", "pattern": r"^\d{3}-\d{3}$"}
            }
        }
        
        # String muy corto
        with pytest.raises(ValidationError, match="String muy corto"):
            validate_json_schema({"short": "ab"}, schema)
        
        # String muy largo
        with pytest.raises(ValidationError, match="String muy largo"):
            validate_json_schema({"short": "this is too long"}, schema)
        
        # No cumple patrón
        with pytest.raises(ValidationError, match="no cumple patrón"):
            validate_json_schema({"pattern": "123456"}, schema)
        
        # Válido
        data = {"short": "valid", "pattern": "123-456"}
        result = validate_json_schema(data, schema)
        assert result == data
    
    @pytest.mark.unit
    def test_number_validations(self):
        """Test validaciones numéricas."""
        schema = {
            "type": "object",
            "properties": {
                "age": {"type": "integer", "minimum": 0, "maximum": 150},
                "score": {"type": "number", "minimum": 0.0, "maximum": 100.0}
            }
        }
        
        # Menor al mínimo
        with pytest.raises(ValidationError, match="menor al mínimo"):
            validate_json_schema({"age": -1}, schema)
        
        # Mayor al máximo
        with pytest.raises(ValidationError, match="mayor al máximo"):
            validate_json_schema({"score": 101.5}, schema)
        
        # Válido
        data = {"age": 25, "score": 85.5}
        result = validate_json_schema(data, schema)
        assert result == data
    
    @pytest.mark.unit
    def test_array_validations(self):
        """Test validaciones de arrays."""
        schema = {
            "type": "object",
            "properties": {
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": 5
                }
            }
        }
        
        # Array vacío
        with pytest.raises(ValidationError, match="Array muy pequeño"):
            validate_json_schema({"tags": []}, schema)
        
        # Array muy grande
        with pytest.raises(ValidationError, match="Array muy grande"):
            validate_json_schema({"tags": ["a", "b", "c", "d", "e", "f"]}, schema)
        
        # Items inválidos
        with pytest.raises(ValidationError, match="Tipo incorrecto"):
            validate_json_schema({"tags": ["valid", 123]}, schema)
        
        # Válido
        data = {"tags": ["python", "testing"]}
        result = validate_json_schema(data, schema)
        assert result == data
    
    @pytest.mark.unit
    def test_additional_properties(self):
        """Test propiedades adicionales."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": False
        }
        
        with pytest.raises(ValidationError, match="Propiedades adicionales no permitidas"):
            validate_json_schema({"name": "John", "extra": "field"}, schema)
    
    @pytest.mark.unit
    def test_enum_validation(self):
        """Test validación enum."""
        schema = {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["active", "inactive", "pending"]}
            }
        }
        
        # Valor no permitido
        with pytest.raises(ValidationError, match="Valor no permitido"):
            validate_json_schema({"status": "invalid"}, schema)
        
        # Válido
        data = {"status": "active"}
        result = validate_json_schema(data, schema)
        assert result == data
    
    @pytest.mark.unit
    def test_nested_object_validation(self, sample_json_schema, valid_test_data):
        """Test validación de objetos anidados."""
        # Usar fixtures de conftest
        result = validate_json_schema(valid_test_data, sample_json_schema)
        assert result == valid_test_data


class TestValidateNotEmpty:
    """Tests para validate_not_empty"""
    
    @pytest.mark.unit
    @pytest.mark.parametrize("value", [
        "non-empty string",
        123,
        ["item"],
        {"key": "value"},
        {1, 2, 3},
        ("a", "b"),
        True,
        False,
        0,
    ])
    def test_valid_non_empty_values(self, value):
        """Test valores no vacíos válidos."""
        result = validate_not_empty(value)
        assert result == value
    
    @pytest.mark.unit
    @pytest.mark.parametrize("value,field", [
        (None, "data"),
        ("", "name"),
        ("   ", "description"),
        ([], "items"),
        ({}, "config"),
        (set(), "tags"),
        ((), "values"),
    ])
    def test_empty_values(self, value, field):
        """Test valores vacíos."""
        with pytest.raises(ValidationError) as exc_info:
            validate_not_empty(value, field_name=field)
        
        assert field in exc_info.value.message
        assert "no puede" in exc_info.value.message
    
    @pytest.mark.unit
    def test_not_empty_custom_field_name(self):
        """Test con nombre de campo personalizado."""
        with pytest.raises(ValidationError) as exc_info:
            validate_not_empty(None, field_name="configuración")
        
        assert "configuración no puede ser None" in exc_info.value.message


class TestValidateInRange:
    """Tests para validate_in_range"""
    
    @pytest.mark.unit
    @pytest.mark.parametrize("value,min_val,max_val", [
        (5, 0, 10),
        (0, 0, 10),
        (10, 0, 10),
        (5.5, 0.0, 10.0),
        (-5, -10, 0),
        (100, None, 200),  # Solo máximo
        (100, 50, None),   # Solo mínimo
    ])
    def test_valid_ranges(self, value, min_val, max_val):
        """Test valores dentro del rango."""
        result = validate_in_range(value, min_val, max_val)
        assert result == value
    
    @pytest.mark.unit
    def test_value_below_minimum(self):
        """Test valor menor al mínimo."""
        with pytest.raises(ValidationError) as exc_info:
            validate_in_range(5, min_value=10, field_name="score")
        
        assert "debe ser mayor o igual a 10" in exc_info.value.message
        assert exc_info.value.details["min"] == 10
        assert exc_info.value.details["actual"] == 5
    
    @pytest.mark.unit
    def test_value_above_maximum(self):
        """Test valor mayor al máximo."""
        with pytest.raises(ValidationError) as exc_info:
            validate_in_range(150, max_value=100, field_name="age")
        
        assert "debe ser menor o igual a 100" in exc_info.value.message
        assert exc_info.value.details["max"] == 100
        assert exc_info.value.details["actual"] == 150
    
    @pytest.mark.unit
    def test_non_numeric_value(self):
        """Test valor no numérico."""
        with pytest.raises(ValidationError) as exc_info:
            validate_in_range("not a number", 0, 10)
        
        assert "debe ser un número" in exc_info.value.message
    
    @pytest.mark.unit
    def test_range_with_floats(self):
        """Test rango con números flotantes."""
        # Válido
        result = validate_in_range(3.14, 0.0, 5.0)
        assert result == 3.14
        
        # Fuera de rango
        with pytest.raises(ValidationError):
            validate_in_range(3.14, 4.0, 5.0)