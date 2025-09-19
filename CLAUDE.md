# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python helpers library (python-helpers) designed to provide reusable utilities for other projects. The codebase follows SOLID principles and is structured as a collection of independent modules.

## Development Commands

### Installation
```bash
# Using uv (recommended)
uv sync

# Using pip
pip install -e .
```

### Testing
The project includes a Makefile for common tasks. Use `make help` to see all available commands.

```bash
# Quick testing commands
make test              # Run all tests
make test-coverage     # Run tests with coverage report
make test-unit         # Run unit tests only
make test-custom-auth  # Run custom_auth module tests
make test-custom-aws   # Run custom_aws module tests (includes SQS and SNS tests)
make check             # Run lint, type-check and tests
make clean             # Clean temporary files

# Manual commands (if not using make)
uv pip install -e ".[dev]"  # Install dev dependencies
uv run pytest               # Run all tests
uv run pytest --cov=.       # Run with coverage
uv run pytest tests/custom_auth/   # Run specific module tests
uv run pytest -m unit       # Run by markers
```

### Linting and Formatting
```bash
make lint              # Run ruff linter
make format            # Format code with ruff
make type-check        # Run mypy type checking
make pre-commit        # Run format, lint, and unit tests before commit
```

### Running Single Tests
```bash
# Run a specific test file
uv run pytest tests/custom_aws/test_secrets.py

# Run a specific test function
uv run pytest tests/custom_aws/test_secrets.py::TestParseSecretJson::test_parse_with_required_fields_success

# Run tests matching a pattern
uv run pytest -k "test_cognito"

# Run tests with detailed output
make test-verbose      # Or: uv run pytest -vv -s
```

### Package Management
- This project uses `pyproject.toml` for dependency management
- Minimum Python version: 3.13
- Key dependencies: boto3, starlette, dotenv

## Architecture

### Module Structure
The project is organized into independent modules, each serving a specific purpose:

- **custom_auth/**: Authentication utilities
  - `middleware.py`: Starlette/FastAPI middleware for API key authentication
  - Supports multiple authentication methods (Bearer token, X-API-Key header, query parameter)
  - Includes `create_api_key_verifier()` for FastAPI dependency-based authentication

- **custom_aws/**: AWS service utilities  
  - `cognito.py`: AWS Cognito User Pools authentication utilities
  - `credentials.py`: Flexible AWS credentials management with multiple providers
  - `secrets.py`: AWS Secrets Manager integration
  - `sqs.py`: Amazon SQS message queue utilities
  - `sns.py`: Amazon SNS notification service utilities
  - Provides `CognitoManager` class for user registration, authentication, and management
  - Provides `test_cognito_connection()` for testing Cognito connectivity
  - Provides `get_boto3_session()`, `assume_role_session()`, `validate_credentials()` for credential management
  - Provides `get_secret_fields()` for retrieving specific fields from JSON secrets
  - Provides `send_message()`, `receive_messages()`, `delete_message()` for SQS operations
  - Provides `publish_message()`, `subscribe()`, `unsubscribe()` for SNS operations
  - Includes robust error handling for AWS exceptions
  - Supports AWS_PROFILE environment variable for credential management

### Design Patterns
- Each module exposes its public API through `__init__.py` files
- Error handling uses custom exception hierarchy based on `BaseError`
- Middleware pattern for authentication (compatible with Starlette/FastAPI)
- All modules are designed to be imported and used independently

### Test Structure
Tests are organized under `tests/` directory mirroring the source structure:
- Tests use pytest with markers: `unit`, `integration`, `integration_real`, `slow`
- Mocking uses `moto` library for AWS services
- Common fixtures are defined in `tests/conftest.py`

### Important Notes from CLAUDE.local.md
- Use SOLID principles when creating software
- You are an expert Python developer
- Use Python UV environment for this project
- Do what has been asked; nothing more, nothing less
- Never create files unless absolutely necessary
- Always prefer editing existing files over creating new ones

## Documentation
Comprehensive documentation is available in the `/docs` directory:
- `docs/index.md` - Main documentation index
- `docs/custom_auth.md` - Authentication middleware documentation
- `docs/custom_aws.md` - AWS utilities documentation
- `docs/custom_aws_cognito.md` - AWS Cognito authentication documentation
- `docs/custom_aws_credentials.md` - AWS credentials management documentation
- `docs/custom_aws_sns.md` - Amazon SNS utilities documentation
- `docs/custom_aws_sqs.md` - Amazon SQS utilities documentation

## Spanish Language Context
The codebase uses Spanish for documentation and comments. Maintain consistency by continuing to use Spanish for:
- Docstrings
- Comments
- Commit messages (format: "Add: feature" or "Fix: issue")
- User-facing messages