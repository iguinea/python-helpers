"""
Validation utilities - Funciones de validación comunes

Proporciona funciones para validar datos comunes como emails, URLs, esquemas JSON, etc.
"""

import re
import json
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse
from .errors import ValidationError


def validate_email(email: str) -> str:
    """
    Valida que una cadena sea un email válido.
    
    Args:
        email: String a validar
        
    Returns:
        str: Email validado (normalizado)
        
    Raises:
        ValidationError: Si el email no es válido
        
    Example:
        >>> validate_email("user@example.com")
        'user@example.com'
    """
    if not email or not isinstance(email, str):
        raise ValidationError("Email no puede estar vacío", field="email", value=email)
    
    # Normalizar email
    email = email.strip().lower()
    
    # Patrón básico de email
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(pattern, email):
        raise ValidationError(
            "Formato de email inválido",
            field="email",
            value=email,
            details={"pattern": pattern}
        )
    
    return email


def validate_url(url: str, schemes: Optional[List[str]] = None) -> str:
    """
    Valida que una cadena sea una URL válida.
    
    Args:
        url: String a validar
        schemes: Esquemas permitidos (default: ["http", "https"])
        
    Returns:
        str: URL validada
        
    Raises:
        ValidationError: Si la URL no es válida
        
    Example:
        >>> validate_url("https://example.com")
        'https://example.com'
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL no puede estar vacía", field="url", value=url)
    
    if schemes is None:
        schemes = ["http", "https"]
    
    try:
        result = urlparse(url)
        
        # Verificar que tenga esquema y host
        if not all([result.scheme, result.netloc]):
            raise ValidationError(
                "URL debe tener esquema y host",
                field="url",
                value=url,
                details={"parsed": result._asdict()}
            )
        
        # Verificar esquema permitido
        if result.scheme not in schemes:
            raise ValidationError(
                f"Esquema URL no permitido: {result.scheme}",
                field="url",
                value=url,
                details={"allowed_schemes": schemes, "found": result.scheme}
            )
        
        return url
        
    except ValidationError:
        # Re-lanzar ValidationError tal como está
        raise
    except Exception as e:
        raise ValidationError(
            "URL inválida",
            field="url",
            value=url,
            cause=e
        )


def validate_json_schema(data: Any, schema: Dict[str, Any]) -> Any:
    """
    Valida datos contra un esquema JSON simple.
    
    Args:
        data: Datos a validar
        schema: Esquema de validación
        
    Returns:
        Any: Datos validados
        
    Raises:
        ValidationError: Si los datos no cumplen con el esquema
        
    Example:
        >>> schema = {
        ...     "type": "object",
        ...     "required": ["name", "age"],
        ...     "properties": {
        ...         "name": {"type": "string"},
        ...         "age": {"type": "integer", "minimum": 0}
        ...     }
        ... }
        >>> validate_json_schema({"name": "Juan", "age": 25}, schema)
    """
    def validate_type(value: Any, expected_type: str) -> bool:
        type_map = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
            "null": type(None)
        }
        
        if expected_type not in type_map:
            return True
            
        return isinstance(value, type_map[expected_type])
    
    def validate_value(value: Any, schema: Dict[str, Any], path: str = "") -> Any:
        # Validar tipo
        if "type" in schema:
            if not validate_type(value, schema["type"]):
                raise ValidationError(
                    f"Tipo incorrecto en {path}",
                    field=path,
                    value=value,
                    details={
                        "expected_type": schema["type"],
                        "actual_type": type(value).__name__
                    }
                )
        
        # Validaciones específicas por tipo
        if schema.get("type") == "string":
            if "minLength" in schema and len(value) < schema["minLength"]:
                raise ValidationError(
                    f"String muy corto en {path}",
                    field=path,
                    value=value,
                    details={"minLength": schema["minLength"], "actual": len(value)}
                )
            
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                raise ValidationError(
                    f"String muy largo en {path}",
                    field=path,
                    value=value,
                    details={"maxLength": schema["maxLength"], "actual": len(value)}
                )
            
            if "pattern" in schema and not re.match(schema["pattern"], value):
                raise ValidationError(
                    f"String no cumple patrón en {path}",
                    field=path,
                    value=value,
                    details={"pattern": schema["pattern"]}
                )
        
        elif schema.get("type") in ["integer", "number"]:
            if "minimum" in schema and value < schema["minimum"]:
                raise ValidationError(
                    f"Valor menor al mínimo en {path}",
                    field=path,
                    value=value,
                    details={"minimum": schema["minimum"]}
                )
            
            if "maximum" in schema and value > schema["maximum"]:
                raise ValidationError(
                    f"Valor mayor al máximo en {path}",
                    field=path,
                    value=value,
                    details={"maximum": schema["maximum"]}
                )
        
        elif schema.get("type") == "array":
            if "items" in schema:
                for i, item in enumerate(value):
                    validate_value(item, schema["items"], f"{path}[{i}]")
            
            if "minItems" in schema and len(value) < schema["minItems"]:
                raise ValidationError(
                    f"Array muy pequeño en {path}",
                    field=path,
                    details={"minItems": schema["minItems"], "actual": len(value)}
                )
            
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                raise ValidationError(
                    f"Array muy grande en {path}",
                    field=path,
                    details={"maxItems": schema["maxItems"], "actual": len(value)}
                )
        
        elif schema.get("type") == "object":
            # Validar propiedades requeridas
            if "required" in schema:
                missing = [field for field in schema["required"] if field not in value]
                if missing:
                    raise ValidationError(
                        f"Campos requeridos faltantes en {path}",
                        field=path,
                        details={"missing_fields": missing}
                    )
            
            # Validar propiedades
            if "properties" in schema:
                for prop, prop_schema in schema["properties"].items():
                    if prop in value:
                        validate_value(
                            value[prop],
                            prop_schema,
                            f"{path}.{prop}" if path else prop
                        )
            
            # Validar propiedades adicionales
            if schema.get("additionalProperties") is False:
                extra = set(value.keys()) - set(schema.get("properties", {}).keys())
                if extra:
                    raise ValidationError(
                        f"Propiedades adicionales no permitidas en {path}",
                        field=path,
                        details={"extra_fields": list(extra)}
                    )
        
        # Validar enum
        if "enum" in schema and value not in schema["enum"]:
            raise ValidationError(
                f"Valor no permitido en {path}",
                field=path,
                value=value,
                details={"allowed_values": schema["enum"]}
            )
        
        return value
    
    return validate_value(data, schema)


def validate_not_empty(value: Any, field_name: str = "value") -> Any:
    """
    Valida que un valor no esté vacío.
    
    Args:
        value: Valor a validar
        field_name: Nombre del campo para mensajes de error
        
    Returns:
        Any: Valor validado
        
    Raises:
        ValidationError: Si el valor está vacío
    """
    if value is None:
        raise ValidationError(f"{field_name} no puede ser None", field=field_name)
    
    if isinstance(value, str) and not value.strip():
        raise ValidationError(f"{field_name} no puede estar vacío", field=field_name)
    
    if isinstance(value, (list, dict, set, tuple)) and len(value) == 0:
        raise ValidationError(f"{field_name} no puede estar vacío", field=field_name)
    
    return value


def validate_in_range(
    value: Union[int, float],
    min_value: Optional[Union[int, float]] = None,
    max_value: Optional[Union[int, float]] = None,
    field_name: str = "value"
) -> Union[int, float]:
    """
    Valida que un número esté dentro de un rango.
    
    Args:
        value: Valor a validar
        min_value: Valor mínimo permitido
        max_value: Valor máximo permitido
        field_name: Nombre del campo para mensajes de error
        
    Returns:
        Union[int, float]: Valor validado
        
    Raises:
        ValidationError: Si el valor está fuera del rango
    """
    if not isinstance(value, (int, float)):
        raise ValidationError(
            f"{field_name} debe ser un número",
            field=field_name,
            value=value
        )
    
    if min_value is not None and value < min_value:
        raise ValidationError(
            f"{field_name} debe ser mayor o igual a {min_value}",
            field=field_name,
            value=value,
            details={"min": min_value, "actual": value}
        )
    
    if max_value is not None and value > max_value:
        raise ValidationError(
            f"{field_name} debe ser menor o igual a {max_value}",
            field=field_name,
            value=value,
            details={"max": max_value, "actual": value}
        )
    
    return value