"""
AWS Utilities for SAP MCP Server

This module provides utility functions for interacting with AWS services,
particularly AWS Secrets Manager for secure credential management.
"""

import json
import os
from typing import Optional, Dict, Any, Union
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def _get_secret_value(
    secret_name: str, region_name: Optional[str] = None
) -> Union[str, bytes]:
    """
    Retrieve a secret value from AWS Secrets Manager.

    This is the base function that handles AWS client creation, secret retrieval,
    and error handling. It returns the raw secret value without parsing.

    Args:
        secret_name: The name or ARN of the secret in AWS Secrets Manager
        region_name: AWS region where the secret is stored (default: from environment)

    Returns:
        Union[str, bytes]: The secret value as string or bytes

    Raises:
        ValueError: If the secret is not found or request is invalid
        PermissionError: If access is denied to the secret
        NoCredentialsError: If AWS credentials are not configured
        ClientError: For other AWS API errors
    """
    # Use provided region or fall back to environment variable or default
    if not region_name:
        region_name = os.environ.get("AWS_DEFAULT_REGION", "eu-west-1")

    # Create a Secrets Manager client
    try:
        session = boto3.Session()
        client = session.client(service_name="secretsmanager", region_name=region_name)
    except NoCredentialsError:
        raise NoCredentialsError()

    try:
        # Retrieve the secret
        response = client.get_secret_value(SecretId=secret_name)

        # Return the appropriate value
        if "SecretString" in response:
            return response["SecretString"]
        elif "SecretBinary" in response:
            return response["SecretBinary"]
        else:
            raise ValueError(f"Secret {secret_name} has no value")

    except ClientError as e:
        # Handle specific AWS errors
        error_code = e.response["Error"]["Code"]

        if error_code == "ResourceNotFoundException":
            raise ValueError(f"Secret {secret_name} not found in region {region_name}")
        elif error_code == "InvalidRequestException":
            raise ValueError(f"Invalid request for secret {secret_name}: {e}")
        elif error_code == "InvalidParameterException":
            raise ValueError(f"Invalid parameter for secret {secret_name}: {e}")
        elif error_code == "AccessDeniedException":
            raise PermissionError(
                f"Access denied to secret {secret_name}. Check IAM permissions for secretsmanager:GetSecretValue"
            )
        else:
            # Re-raise the original exception for other errors
            raise


def parse_secret_json(
    secret_value: str, required_fields: Optional[list[str]] = None
) -> Dict[str, Any]:
    """
    Parse a JSON secret and validate required fields.

    Args:
        secret_value: The secret string to parse
        required_fields: List of field names that must be present in the JSON

    Returns:
        Dict[str, Any]: The parsed JSON data

    Raises:
        ValueError: If JSON is invalid or required fields are missing
    """
    try:
        data = json.loads(secret_value)
    except json.JSONDecodeError as e:
        raise ValueError(f"Secret value is not valid JSON: {e}")

    if not isinstance(data, dict):
        raise ValueError(
            f"Secret value must be a JSON object, got {type(data).__name__}"
        )

    # Validate required fields if specified
    if required_fields:
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            raise ValueError(
                f"Secret missing required fields: {', '.join(missing_fields)}"
            )

    return data


def get_secret_fields(
    secret_name: str,
    fields: list[str],
    region_name: Optional[str] = None,
    allow_missing: bool = False,
) -> Dict[str, Any]:
    """
    Retrieve specific fields from a JSON secret in AWS Secrets Manager.

    This function fetches a secret and returns only the requested fields
    as a dictionary. The secret must be stored as a JSON object.

    Args:
        secret_name: The name or ARN of the secret in AWS Secrets Manager
        fields: List of field names to retrieve from the secret
        region_name: AWS region where the secret is stored (default: from environment)
        allow_missing: If True, missing fields are ignored. If False, raises ValueError
                      for missing fields (default: False)

    Returns:
        Dict[str, Any]: Dictionary containing the requested fields and their values

    Raises:
        ValueError: If the secret is not JSON, fields list is empty, or required fields
                   are missing (when allow_missing=False)
        ClientError: If there's an AWS API error
        NoCredentialsError: If AWS credentials are not configured

    Examples:
        >>> # Get specific fields from a secret
        >>> data = get_secret_fields("myapp/config", ["api_key", "endpoint"])
        >>> print(data)  # {'api_key': 'abc123', 'endpoint': 'https://api.example.com'}

        >>> # Allow missing fields
        >>> data = get_secret_fields("myapp/config", ["api_key", "optional_field"], allow_missing=True)
        >>> print(data)  # {'api_key': 'abc123'} - optional_field is missing but allowed
    """
    # Validate input
    if not fields:
        raise ValueError("Fields list cannot be empty")

    # Get the secret value
    secret_value = _get_secret_value(secret_name, region_name)

    # Ensure it's a string (not binary)
    if isinstance(secret_value, bytes):
        raise ValueError(
            f"Secret {secret_name} is stored as binary, expected JSON string"
        )

    # Parse the JSON secret
    if allow_missing:
        # Don't require fields during parsing
        secret_data = parse_secret_json(secret_value)
    else:
        # Require all fields during parsing
        secret_data = parse_secret_json(secret_value, required_fields=fields)

    # Extract only the requested fields
    result = {}
    missing_fields = []

    for field in fields:
        if field in secret_data:
            result[field] = secret_data[field]
        else:
            missing_fields.append(field)

    # Handle missing fields
    if missing_fields and not allow_missing:
        raise ValueError(
            f"Secret {secret_name} missing fields: {', '.join(missing_fields)}"
        )

    # Ensure at least one field was found
    if not result:
        raise ValueError(
            f"Secret {secret_name} contains none of the requested fields: {', '.join(fields)}"
        )

    return result


# Convenience function for quick testing
def test_secrets_manager_connection(region_name: Optional[str] = None) -> bool:
    """
    Test if AWS Secrets Manager is accessible.

    Args:
        region_name: AWS region to test (optional)

    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        if not region_name:
            region_name = os.environ.get("AWS_DEFAULT_REGION", "eu-west-1")

        session = boto3.Session()
        client = session.client(service_name="secretsmanager", region_name=region_name)
        # List secrets (with limit 1) to test connection
        client.list_secrets(MaxResults=1)
        return True
    except Exception as e:
        print(f"AWS Secrets Manager connection test failed: {e}")
        return False
