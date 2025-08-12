# ========================================
# 5. SERVICIO COGNITO (cognito_service.py)
# ========================================
import hashlib
import hmac
import base64
import uuid
from typing import Optional, Dict, Any
from pycognito import Cognito
from pycognito.exceptions import (
    TokenVerificationException,
    ForceChangePasswordException,
)
import boto3
from botocore.exceptions import ClientError

from .config import Settings
from .schemas import UserRegister


class CognitoService:
    def __init__(self, settings):
        self.settings = settings
        self.client = self._retrieve_client(settings)

    def _retrieve_session(self, settings):
        """Retrieve the session from the client"""
        if settings.aws_profile:
            return boto3.Session(profile_name=settings.aws_profile)
        elif settings.aws_access_key_id and settings.aws_secret_access_key:
            return boto3.Session(
                aws_access_key_id=settings.aws_access_key_id,
                aws_secret_access_key=settings.aws_secret_access_key,
            )
        else:
            return boto3.Session()

    def _retrieve_client(self, settings):
        """Retrieve the client from the session"""
        # Configurar cliente boto3 con las credenciales apropiadas
        if settings.aws_profile:
            session = boto3.Session(profile_name=settings.aws_profile)
            self.client = session.client("cognito-idp", region_name=settings.aws_region)
        elif settings.aws_access_key_id and settings.aws_secret_access_key:
            self.client = boto3.client(
                "cognito-idp",
                region_name=settings.aws_region,
                aws_access_key_id=settings.aws_access_key_id,
                aws_secret_access_key=settings.aws_secret_access_key,
            )
        else:
            self.client = boto3.client("cognito-idp", region_name=settings.aws_region)

        return self.client

    def _get_secret_hash(self, username: str) -> str:
        """Calculate secret hash for Cognito if app client has a secret"""
        if not self.settings.cognito_app_client_secret:
            return None

        message = bytes(username + self.settings.cognito_app_client_id, "utf-8")
        secret = bytes(self.settings.cognito_app_client_secret, "utf-8")
        dig = hmac.new(secret, msg=message, digestmod=hashlib.sha256).digest()
        return base64.b64encode(dig).decode()

    def _get_cognito_user(self, username: str) -> Cognito:
        """Get Cognito user instance"""
        return Cognito(
            self.settings.cognito_user_pool_id,
            self.settings.cognito_app_client_id,
            client_secret=self.settings.cognito_app_client_secret,
            username=username,
            user_pool_region=self.settings.aws_region,
            session=self._retrieve_session(self.settings),
        )

    def _get_username_by_email(self, email: str) -> Optional[str]:
        """Get username by email when using email alias"""
        try:
            response = self.client.list_users(
                UserPoolId=self.settings.cognito_user_pool_id,
                Filter=f'email = "{email}"',
                Limit=1,
            )

            if response["Users"]:
                return response["Users"][0]["Username"]
            return None
        except ClientError:
            return None

    async def register_user(self, user_data: UserRegister) -> Dict[str, Any]:
        """Register a new user"""
        try:
            # Verificar si el email ya existe
            existing_user = self._get_username_by_email(user_data.email)
            if existing_user:
                raise ValueError("User with this email already exists")

            # Usar la parte del email antes del @ como username base
            email_prefix = user_data.email.split("@")[0]
            # Agregar un sufijo único para evitar colisiones
            unique_suffix = str(uuid.uuid4())[:8]
            username = f"{email_prefix}_{unique_suffix}"
            secret_hash = self._get_secret_hash(username)

            params = {
                "ClientId": self.settings.cognito_app_client_id,
                "Username": username,
                "Password": user_data.password,
                "UserAttributes": [
                    {"Name": "email", "Value": user_data.email},
                    {"Name": "name", "Value": user_data.full_name},
                ],
            }

            if user_data.phone_number:
                params["UserAttributes"].append(
                    {"Name": "phone_number", "Value": user_data.phone_number}
                )

            if secret_hash:
                params["SecretHash"] = secret_hash

            response = self.client.sign_up(**params)

            return {
                "user_sub": response["UserSub"],
                "email": user_data.email,
                "username": username,  # Incluir el username generado
                "confirmation_required": not response["UserConfirmed"],
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]

            if error_code == "UsernameExistsException":
                raise ValueError("User with this email already exists")
            elif error_code == "InvalidPasswordException":
                raise ValueError(error_message)
            else:
                raise Exception(f"Registration failed: {error_message}")

    async def confirm_email(self, email: str, code: str) -> bool:
        """Confirm user email with verification code"""
        try:
            # Obtener el username real cuando se usa email alias
            username = self._get_username_by_email(email) or email
            secret_hash = self._get_secret_hash(username)

            params = {
                "ClientId": self.settings.cognito_app_client_id,
                "Username": username,
                "ConfirmationCode": code,
            }

            if secret_hash:
                params["SecretHash"] = secret_hash

            self.client.confirm_sign_up(**params)
            return True

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "CodeMismatchException":
                raise ValueError("Invalid verification code")
            elif error_code == "ExpiredCodeException":
                raise ValueError("Verification code has expired")
            else:
                raise Exception(
                    f"Email confirmation failed: {e.response['Error']['Message']}"
                )

    async def login(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate user and return tokens"""
        try:
            # Obtener el username real cuando se usa email alias
            username = self._get_username_by_email(email) or email
            cognito_user = self._get_cognito_user(username)

            # Authenticate user - no retorna nada, almacena tokens como atributos
            cognito_user.authenticate(password=password)
            
            # Acceder a los tokens desde los atributos del objeto cognito_user
            # Nota: expires_in puede no estar disponible en algunas versiones de pycognito
            result = {
                "access_token": cognito_user.access_token,
                "refresh_token": cognito_user.refresh_token,
                "id_token": cognito_user.id_token,
            }
            
            # Agregar expires_in si está disponible
            if hasattr(cognito_user, 'expires_in'):
                result["expires_in"] = cognito_user.expires_in
            else:
                # Valor por defecto de Cognito (1 hora = 3600 segundos)
                result["expires_in"] = 3600
                
            return result

        except ForceChangePasswordException:
            raise ValueError("Password change required")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "UserNotConfirmedException":
                raise ValueError("Email not verified")
            elif error_code == "NotAuthorizedException":
                raise ValueError("Invalid email or password")
            else:
                raise ValueError(f"Login failed: {e.response['Error']['Message']}")
        except Exception as e:
            if "UserNotConfirmedException" in str(e):
                raise ValueError("Email not verified")
            elif "NotAuthorizedException" in str(e):
                raise ValueError("Invalid email or password")
            else:
                raise Exception(f"Login failed: {str(e)}")

    async def initiate_password_reset(self, email: str) -> bool:
        """Send password reset code to user's email"""
        try:
            secret_hash = self._get_secret_hash(email)

            params = {
                "ClientId": self.settings.cognito_app_client_id,
                "Username": email,
            }

            if secret_hash:
                params["SecretHash"] = secret_hash

            self.client.forgot_password(**params)
            return True

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "UserNotFoundException":
                # Don't reveal if user exists for security
                return True
            else:
                raise Exception(
                    f"Password reset failed: {e.response['Error']['Message']}"
                )

    async def confirm_password_reset(
        self, email: str, code: str, new_password: str
    ) -> bool:
        """Confirm password reset with code"""
        try:
            secret_hash = self._get_secret_hash(email)

            params = {
                "ClientId": self.settings.cognito_app_client_id,
                "Username": email,
                "ConfirmationCode": code,
                "Password": new_password,
            }

            if secret_hash:
                params["SecretHash"] = secret_hash

            self.client.confirm_forgot_password(**params)
            return True

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "CodeMismatchException":
                raise ValueError("Invalid reset code")
            elif error_code == "ExpiredCodeException":
                raise ValueError("Reset code has expired")
            else:
                raise Exception(
                    f"Password reset confirmation failed: {e.response['Error']['Message']}"
                )

    async def refresh_tokens(self, refresh_token: str) -> Dict[str, Any]:
        """Get new tokens using refresh token"""
        try:
            params = {
                "ClientId": self.settings.cognito_app_client_id,
                "AuthFlow": "REFRESH_TOKEN_AUTH",
                "AuthParameters": {"REFRESH_TOKEN": refresh_token},
            }

            if self.settings.cognito_app_client_secret:
                # Note: Secret hash is not used with refresh token
                pass

            response = self.client.initiate_auth(**params)

            return {
                "access_token": response["AuthenticationResult"]["AccessToken"],
                "id_token": response["AuthenticationResult"]["IdToken"],
                "expires_in": response["AuthenticationResult"]["ExpiresIn"],
            }

        except ClientError as e:
            raise Exception(f"Token refresh failed: {e.response['Error']['Message']}")

    async def logout(self, access_token: str) -> bool:
        """Logout user (revoke tokens)"""
        try:
            self.client.global_sign_out(AccessToken=access_token)
            return True
        except ClientError as e:
            # If token is already invalid, consider it a successful logout
            if e.response["Error"]["Code"] == "NotAuthorizedException":
                return True
            raise Exception(f"Logout failed: {e.response['Error']['Message']}")

    async def setup_mfa(self, access_token: str) -> Dict[str, Any]:
        """Setup software token MFA"""
        try:
            response = self.client.associate_software_token(AccessToken=access_token)

            # Generate QR code URL for authenticator apps
            secret_code = response["SecretCode"]

            # Get user details for QR code
            user_info = self.client.get_user(AccessToken=access_token)
            email = next(
                attr["Value"]
                for attr in user_info["UserAttributes"]
                if attr["Name"] == "email"
            )

            qr_code_url = f"otpauth://totp/{email}?secret={secret_code}&issuer=YourApp"

            return {
                "secret_code": secret_code,
                "qr_code_url": qr_code_url,
                "session": response.get("Session"),
            }

        except ClientError as e:
            raise Exception(f"MFA setup failed: {e.response['Error']['Message']}")

    async def verify_mfa_setup(self, access_token: str, code: str) -> bool:
        """Verify and enable MFA"""
        try:
            self.client.verify_software_token(AccessToken=access_token, UserCode=code)

            # Enable MFA for the user
            self.client.set_user_mfa_preference(
                AccessToken=access_token,
                SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
            )

            return True

        except ClientError as e:
            if e.response["Error"]["Code"] == "CodeMismatchException":
                raise ValueError("Invalid MFA code")
            raise Exception(
                f"MFA verification failed: {e.response['Error']['Message']}"
            )
