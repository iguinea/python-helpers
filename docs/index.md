# Python Helpers - Documentación

Bienvenido a la documentación de Python Helpers, una colección de utilidades reutilizables para proyectos Python.

## 📚 Módulos Disponibles

### 🔐 [Custom Auth](custom_auth.md)
Middleware de autenticación por API key para aplicaciones Starlette/FastAPI.

**Características principales:**
- Múltiples métodos de autenticación (Bearer, X-API-Key, query parameter)
- Rutas públicas configurables
- Fácil integración con frameworks web

### ☁️ [Custom AWS](custom_aws.md)
Utilidades para servicios AWS, especialmente AWS Secrets Manager.

**Características principales:**
- Recuperación segura de secretos
- Parsing automático de JSON
- Manejo robusto de errores AWS
- Validación de campos requeridos


## 🚀 Inicio Rápido

### Instalación

```bash
# Usando pip
pip install -e .

# Usando uv (recomendado)
uv pip install -e .
```

### Ejemplo Básico

```python
# Autenticación
from custom_auth.middleware import create_authentication_middleware

middleware = create_authentication_middleware(api_key="secret-key")

# AWS Secrets
from custom_aws.secrets import get_secret_fields

config = get_secret_fields("myapp/config", ["api_key", "endpoint"])
```

## 📖 Guías de Uso

### Configuración por Ambiente

Todos los módulos soportan configuración basada en el ambiente:

```python
import os

# Para AWS
os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"

# Para autenticación
api_key = os.environ.get("API_KEY")
```

### Mejores Prácticas

1. **Seguridad**
   - Nunca hardcodees credenciales
   - Usa variables de entorno o gestores de secretos
   - Valida todas las entradas de usuario

2. **Testing**
   - Usa mocks para servicios externos (AWS, APIs)
   - Valida casos límite y errores
   - Mantén los tests rápidos y determinísticos

## 🧪 Testing

Ejecutar todos los tests:
```bash
make test
```

Ejecutar tests con cobertura:
```bash
make test-coverage
```

Ejecutar tests de un módulo específico:
```bash
make test-custom-auth
make test-custom-aws
```

## 🤝 Contribuir

1. Fork el proyecto
2. Crea tu feature branch (`git checkout -b feature/nueva-funcionalidad`)
3. Escribe tests para tu funcionalidad
4. Asegúrate de que todos los tests pasen
5. Commit tus cambios (`git commit -m 'Add: nueva funcionalidad'`)
6. Push a la branch (`git push origin feature/nueva-funcionalidad`)
7. Abre un Pull Request

## 📝 Principios de Diseño

Este proyecto sigue los principios SOLID:

- **Single Responsibility**: Cada módulo y clase tiene una responsabilidad única
- **Open/Closed**: Los módulos son extensibles sin modificar el código existente
- **Liskov Substitution**: Las implementaciones son intercambiables
- **Interface Segregation**: Interfaces específicas y enfocadas
- **Dependency Inversion**: Dependencias mediante abstracciones

## 🔗 Enlaces Útiles

- [Repositorio del Proyecto](https://github.com/tu-usuario/python-helpers)
- [Reporte de Issues](https://github.com/tu-usuario/python-helpers/issues)
- [Changelog](../CHANGELOG.md)

## 📄 Licencia

Este proyecto es privado y de uso interno.

---

*Última actualización: 2024*