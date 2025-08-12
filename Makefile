# Makefile para Python Helpers

# Variables
PYTHON := python
UV := uv
PYTEST := $(UV) run pytest
COVERAGE := $(UV) run coverage
PROJECT_NAME := python-helpers

# Colores para output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

.PHONY: help
help: ## Muestra esta ayuda
	@echo "$(GREEN)Comandos disponibles:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

.PHONY: install
install: ## Instala las dependencias del proyecto
	@echo "$(GREEN)Instalando dependencias...$(NC)"
	$(UV) pip install -e .

.PHONY: install-dev
install-dev: ## Instala las dependencias de desarrollo
	@echo "$(GREEN)Instalando dependencias de desarrollo...$(NC)"
	$(UV) pip install -e ".[dev]"

.PHONY: test
test: ## Ejecuta todos los tests
	@echo "$(GREEN)Ejecutando tests...$(NC)"
	$(PYTEST) -v

.PHONY: test-unit
test-unit: ## Ejecuta solo tests unitarios
	@echo "$(GREEN)Ejecutando tests unitarios...$(NC)"
	$(PYTEST) -v -m unit

.PHONY: test-integration
test-integration: ## Ejecuta solo tests de integración
	@echo "$(GREEN)Ejecutando tests de integración...$(NC)"
	$(PYTEST) -v -m integration

.PHONY: test-coverage
test-coverage: ## Ejecuta tests con reporte de cobertura
	@echo "$(GREEN)Ejecutando tests con cobertura...$(NC)"
	$(PYTEST) --cov=. --cov-report=term --cov-report=html --cov-report=xml

.PHONY: test-coverage-html
test-coverage-html: test-coverage ## Ejecuta tests con cobertura y abre el reporte HTML
	@echo "$(GREEN)Abriendo reporte de cobertura...$(NC)"
	@python -m webbrowser htmlcov/index.html

.PHONY: test-custom-auth
test-custom-auth: ## Ejecuta tests del módulo custom_auth
	@echo "$(GREEN)Ejecutando tests de custom_auth...$(NC)"
	$(PYTEST) -v tests/custom_auth/

.PHONY: test-custom-aws
test-custom-aws: ## Ejecuta tests del módulo custom_aws
	@echo "$(GREEN)Ejecutando tests de custom_aws...$(NC)"
	$(PYTEST) -v tests/custom_aws/

.PHONY: test-custom-cognito
test-custom-cognito: ## Ejecuta tests del módulo custom_cognito
	@echo "$(GREEN)Ejecutando tests de custom_cognito...$(NC)"
	$(PYTEST) -v tests/custom_cognito/
	@echo "$(GREEN)Ejecutando tests internos de custom_cognito...$(NC)"
	cd custom_cognito && $(PYTHON) -m pytest tests/ -v

.PHONY: test-custom-cognito-real
test-custom-cognito-real: ## Ejecuta tests de integración real con AWS Cognito (requiere credenciales)
	@echo "$(YELLOW)⚠️  ADVERTENCIA: Estos tests crearán usuarios reales en tu User Pool de Cognito$(NC)"
	@echo "$(YELLOW)Solo ejecuta estos tests contra un User Pool de desarrollo/testing$(NC)"
	@echo "$(GREEN)Ejecutando tests de integración real con AWS Cognito...$(NC)"
	cd custom_cognito && $(PYTHON) -m pytest -m integration_real tests/ -v

.PHONY: test-custom-cognito-real-delete-users
test-custom-cognito-real-delete-users: ## Ejecuta tests de integración real con AWS Cognito (requiere credenciales)
	@echo "$(YELLOW)⚠️  ADVERTENCIA: Estos tests eliminarán usuarios reales en tu User Pool de Cognito$(NC)"
	@echo "$(YELLOW)Solo ejecuta estos tests contra un User Pool de desarrollo/testing$(NC)"
	@echo "$(GREEN)Ejecutando tests de integración real con AWS Cognito...$(NC)"
	python -m pytest tests/custom_cognito/test_user_lifecycle.py -v -s

# Herramientas de Cognito
.PHONY: cognito-list-users
cognito-list-users: ## Lista todos los usuarios en Cognito
	@echo "$(GREEN)Listando usuarios de Cognito...$(NC)"
	$(PYTHON) tools/cognito/list_cognito_users.py

.PHONY: cognito-disable-users
cognito-disable-users: ## Desactiva todos los usuarios en Cognito (requiere confirmación)
	@echo "$(RED)⚠️  ADVERTENCIA: Esto desactivará TODOS los usuarios en Cognito$(NC)"
	@echo "$(GREEN)Ejecutando desactivación de usuarios...$(NC)"
	$(PYTHON) tools/cognito/disable_cognito_users.py

.PHONY: cognito-delete-users
cognito-delete-users: ## Elimina todos los usuarios en Cognito (requiere confirmación)
	@echo "$(RED)⚠️  ADVERTENCIA: Esto eliminará PERMANENTEMENTE todos los usuarios en Cognito$(NC)"
	@echo "$(GREEN)Ejecutando eliminación de usuarios...$(NC)"
	$(PYTHON) tools/cognito/delete_cognito_users.py

.PHONY: cognito-test-interactive
cognito-test-interactive: ## Ejecuta test interactivo de registro y confirmación
	@echo "$(GREEN)Ejecutando test interactivo de Cognito...$(NC)"
	$(PYTHON) tools/cognito/test_cognito_user_interactive.py

.PHONY: cognito-test-demo
cognito-test-demo: ## Ejecuta demo de registro (sin interacción)
	@echo "$(GREEN)Ejecutando demo de Cognito...$(NC)"
	$(PYTHON) tools/cognito/test_cognito_user_demo.py
	
	
.PHONY: test-watch
test-watch: ## Ejecuta tests en modo watch (requiere pytest-watch)
	@echo "$(GREEN)Ejecutando tests en modo watch...$(NC)"
	$(UV) run ptw -- -v

.PHONY: test-failed
test-failed: ## Re-ejecuta solo los tests que fallaron
	@echo "$(GREEN)Re-ejecutando tests fallidos...$(NC)"
	$(PYTEST) -v --lf

.PHONY: test-verbose
test-verbose: ## Ejecuta tests con output detallado
	@echo "$(GREEN)Ejecutando tests con output detallado...$(NC)"
	$(PYTEST) -vv -s

.PHONY: lint
lint: ## Ejecuta linters (requiere ruff)
	@echo "$(GREEN)Ejecutando linters...$(NC)"
	$(UV) run ruff check .
	$(UV) run ruff format --check .

.PHONY: format
format: ## Formatea el código
	@echo "$(GREEN)Formateando código...$(NC)"
	$(UV) run ruff format .

.PHONY: type-check
type-check: ## Ejecuta verificación de tipos (requiere mypy)
	@echo "$(GREEN)Verificando tipos...$(NC)"
	$(UV) run mypy .

.PHONY: clean
clean: ## Limpia archivos temporales y de cache
	@echo "$(GREEN)Limpiando archivos temporales...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name ".coverage" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "coverage.xml" -delete 2>/dev/null || true

.PHONY: clean-all
clean-all: clean ## Limpia todo incluyendo entorno virtual
	@echo "$(GREEN)Limpiando todo...$(NC)"
	rm -rf .venv

.PHONY: check
check: lint type-check test ## Ejecuta todas las verificaciones (lint, tipos, tests)
	@echo "$(GREEN)✅ Todas las verificaciones pasaron$(NC)"

.PHONY: ci
ci: install-dev check ## Ejecuta el pipeline completo de CI
	@echo "$(GREEN)✅ Pipeline CI completado$(NC)"

.PHONY: pre-commit
pre-commit: format lint test-unit ## Ejecuta verificaciones antes de commit
	@echo "$(GREEN)✅ Listo para commit$(NC)"

.PHONY: docs
docs: ## Genera documentación (placeholder para futuro)
	@echo "$(YELLOW)Generación de documentación no implementada aún$(NC)"

.PHONY: build
build: clean ## Construye el paquete
	@echo "$(GREEN)Construyendo paquete...$(NC)"
	$(UV) build

.PHONY: serve-coverage
serve-coverage: ## Sirve el reporte de cobertura en un servidor local
	@echo "$(GREEN)Sirviendo reporte de cobertura en http://localhost:8000$(NC)"
	@cd htmlcov && python -m http.server 8000

# Targets rápidos
.PHONY: t
t: test ## Alias corto para test

.PHONY: tc
tc: test-coverage ## Alias corto para test-coverage

.PHONY: c
c: clean ## Alias corto para clean