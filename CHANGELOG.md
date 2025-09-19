# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.7]

### Added

- Node.js development environment support (package.json, package-lock.json)

### Removed

- **BREAKING**: AWS Cognito authentication module (`custom_aws.cognito`) completely removed
  - CognitoManager class and all related functionality
  - User registration, email confirmation, and authentication features
  - Password reset and token refresh functionality
  - User profile management capabilities
- Cognito-related documentation (`docs/custom_aws_cognito.md`)
- All Cognito imports and exports from `custom_aws` module

## [0.1.6] - 2025-08-01

### Added

- AWS credentials management utilities (`custom_aws.credentials`)
  - Multiple credential providers: Direct, AssumeRole, Secrets Manager, Environment, Instance Profile
  - `get_boto3_session()` - Flexible session creation with different providers
  - `assume_role_session()` - Simplified AssumeRole functionality
  - `validate_credentials()` - Verify AWS credentials are valid
  - `get_credentials_from_secret()` - Retrieve credentials from Secrets Manager
  - Support for credential caching and refresh
- Comprehensive credentials documentation (`docs/custom_aws_credentials.md`)
- Full test coverage for credentials module

### Changed

- Enhanced AWS utilities with centralized credential management
- Updated documentation with credential management best practices

## [0.1.5] - 2025-08-01

### Added

- Amazon SNS utilities module (`custom_aws.sns`) with comprehensive notification service support
  - `publish_message()` - Publish messages to topics or send SMS directly
  - `publish_batch()` - Publish multiple messages in batch (up to 10)
  - `subscribe()` - Subscribe endpoints to topics (email, SMS, SQS, Lambda, HTTP/S)
  - `unsubscribe()` - Cancel subscriptions
  - `list_subscriptions_by_topic()` - List all topic subscriptions
  - `get_topic_attributes()` - Get topic metadata
  - `set_subscription_attributes()` - Configure subscription filters and policies
  - `confirm_subscription()` - Confirm pending subscriptions
  - `check_sns_connection()` - Verify SNS connectivity
- Comprehensive SNS documentation (`docs/custom_aws_sns.md`)
- Full test coverage for SNS module

### Changed

- Updated documentation to reflect current project structure

### Removed

- References to deprecated `common` module in documentation

## [0.1.4] - 2024-12-20

### Added

- Amazon SQS utilities module (`custom_aws.sqs`) for message queue operations
  - `send_message()` - Send single messages to queues
  - `send_message_batch()` - Send multiple messages in batch (up to 10)
  - `receive_messages()` - Receive messages with long polling support
  - `delete_message()` - Delete processed messages
  - `delete_message_batch()` - Delete multiple messages in batch
  - `get_queue_attributes()` - Get queue metadata and statistics
  - `purge_queue()` - Clear all messages from a queue
  - `check_sqs_connection()` - Verify SQS connectivity
- Comprehensive SQS documentation (`docs/custom_aws_sqs.md`)
- Full test coverage for SQS module

### Changed

- Enhanced README with SQS usage examples
- Updated documentation structure

## [0.1.3] - 2024-12-15

### Added

- FastAPI dependency-based authentication with `create_api_key_verifier()`
- Support for protecting individual endpoints instead of global middleware
- Enhanced authentication documentation with FastAPI examples

### Changed

- Improved authentication middleware flexibility
- Updated README with new authentication patterns

## [0.1.2] - 2024-12-10

### Added

- API key authentication middleware for Starlette/FastAPI applications
- Multiple authentication methods support (Bearer token, X-API-Key header, query parameter)
- Configurable public routes
- Comprehensive test suite for authentication

## [0.1.1] - 2024-12-05

### Added

- AWS Secrets Manager integration (`custom_aws.secrets`)
  - `get_secret_fields()` - Retrieve specific fields from JSON secrets
  - `parse_secret_json()` - Parse and validate JSON secrets
  - `check_secrets_manager_connection()` - Verify connectivity
- Comprehensive documentation for AWS utilities
- Full test coverage with mocking support

### Changed

- Restructured package to use `custom_auth` and `custom_aws` modules
- Improved error handling with custom exceptions

## [0.1.0] - 2024-12-01

### Added

- Initial release of Python Helpers library
- Basic project structure with Makefile
- Testing infrastructure with pytest
- Documentation framework
- Spanish language support for documentation and comments

[0.1.7]: https://github.com/tu-usuario/python-helpers/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/tu-usuario/python-helpers/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/tu-usuario/python-helpers/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/tu-usuario/python-helpers/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/tu-usuario/python-helpers/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/tu-usuario/python-helpers/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/tu-usuario/python-helpers/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tu-usuario/python-helpers/releases/tag/v0.1.0
