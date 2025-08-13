"""
Utilidades AWS Cognito para autenticación de usuarios

Este módulo proporciona la clase CognitoManager para interactuar con AWS Cognito User Pools,
permitiendo registro, autenticación y gestión de usuarios de forma eficiente.
"""

import base64
import hashlib
import hmac
import os
from typing import Optional, Dict, Any
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def _get_cognito_client(region_name: Optional[str] = None):
    """
    Crear un cliente Cognito IDP reutilizable.
    
    Args:
        region_name: Región AWS donde está el User Pool (por defecto: desde el entorno)
        
    Returns:
        boto3.client: Cliente Cognito IDP configurado
        
    Raises:
        NoCredentialsError: Si las credenciales AWS no están configuradas
    """
    if not region_name:
        region_name = os.environ.get("AWS_DEFAULT_REGION", "eu-west-1")
    
    try:
        session = boto3.Session()
        return session.client(service_name="cognito-idp", region_name=region_name)
    except NoCredentialsError:
        raise NoCredentialsError()


def _calculate_secret_hash(username: str, client_id: str, client_secret: str) -> str:
    """
    Calcular el SECRET_HASH requerido cuando el App Client tiene un secret.
    
    Args:
        username: Nombre de usuario o email
        client_id: ID del App Client de Cognito
        client_secret: Secret del App Client
        
    Returns:
        str: Hash codificado en base64
        
    Raises:
        ValueError: Si algún parámetro es None o vacío
    """
    if not username or not client_id or not client_secret:
        raise ValueError("Username, client_id y client_secret son requeridos para SECRET_HASH")
    
    message = bytes(username + client_id, "utf-8")
    secret = bytes(client_secret, "utf-8")
    dig = hmac.new(secret, msg=message, digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()


def test_cognito_connection(
    user_pool_id: str,
    region_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Probar la conexión con AWS Cognito.
    
    Args:
        user_pool_id: ID del User Pool para verificar
        region_name: Región AWS donde está el User Pool
        
    Returns:
        Dict con información del User Pool si la conexión es exitosa
        
    Raises:
        NoCredentialsError: Si las credenciales AWS no están configuradas
        ValueError: Si el User Pool no existe
        ClientError: Para otros errores de AWS
    """
    client = _get_cognito_client(region_name)
    
    try:
        response = client.describe_user_pool(UserPoolId=user_pool_id)
        
        pool_info = response["UserPool"]
        
        return {
            "success": True,
            "user_pool_id": pool_info["Id"],
            "user_pool_name": pool_info.get("Name", ""),
            "status": pool_info.get("Status", ""),
            "user_count": pool_info.get("EstimatedNumberOfUsers", 0),
            "region": region_name or os.environ.get("AWS_DEFAULT_REGION", "eu-west-1")
        }
        
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        
        if error_code == "ResourceNotFoundException":
            raise ValueError(f"User Pool {user_pool_id} no encontrado")
        else:
            raise


class CognitoManager:
    """
    Gestor de operaciones AWS Cognito con cliente reutilizable.
    
    Esta clase proporciona una forma eficiente de realizar múltiples operaciones
    con AWS Cognito reutilizando el mismo cliente, ideal para aplicaciones
    que necesitan hacer múltiples llamadas.
    
    Attributes:
        user_pool_id: ID del User Pool de Cognito
        client_id: ID del App Client
        client_secret: Secret del App Client (opcional)
        region_name: Región AWS donde está el User Pool
        
    Example:
        >>> # Uso básico
        >>> manager = CognitoManager(
        ...     user_pool_id="eu-west-1_XXXXXXXXX",
        ...     client_id="1234567890abcdef",
        ...     client_secret="mi-client-secret"  # Opcional
        ... )
        >>> 
        >>> # Registrar usuario
        >>> result = manager.register_user("usuario@ejemplo.com", "ContraseñaSegura123!")
        >>> print(f"Usuario creado: {result['user_sub']}")
        >>> 
        >>> # Confirmar usuario
        >>> manager.confirm_user("usuario@ejemplo.com", "123456")
        >>> 
        >>> # Autenticar
        >>> tokens = manager.authenticate_user("usuario@ejemplo.com", "ContraseñaSegura123!")
        >>> print(f"Access token: {tokens['access_token']}")
        
        >>> # Uso con context manager
        >>> with CognitoManager(user_pool_id="...", client_id="...") as manager:
        ...     tokens = manager.authenticate_user("user@example.com", "password")
        ...     # El cliente se cierra automáticamente al salir
    """
    
    def __init__(
        self,
        user_pool_id: str,
        client_id: str,
        client_secret: Optional[str] = None,
        region_name: Optional[str] = None
    ):
        """
        Inicializar el gestor de Cognito.
        
        Args:
            user_pool_id: ID del User Pool de Cognito
            client_id: ID del App Client
            client_secret: Secret del App Client (opcional)
            region_name: Región AWS donde está el User Pool (por defecto: desde el entorno)
        """
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.region_name = region_name or os.environ.get("AWS_DEFAULT_REGION", "eu-west-1")
        self._client = None
        self._session = None
    
    @property
    def client(self):
        """
        Cliente Cognito IDP lazy-loaded y reutilizable.
        
        Returns:
            boto3.client: Cliente configurado para cognito-idp
            
        Raises:
            NoCredentialsError: Si las credenciales AWS no están configuradas
        """
        if self._client is None:
            try:
                if self._session is None:
                    self._session = boto3.Session()
                self._client = self._session.client(
                    service_name="cognito-idp",
                    region_name=self.region_name
                )
            except NoCredentialsError:
                raise NoCredentialsError()
        return self._client
    
    def _calculate_secret_hash(self, username: str) -> Optional[str]:
        """
        Calcular el SECRET_HASH para este cliente si tiene secret configurado.
        
        Args:
            username: Nombre de usuario o email
            
        Returns:
            str: Hash calculado o None si no hay client_secret
        """
        if not self.client_secret:
            return None
        return _calculate_secret_hash(username, self.client_id, self.client_secret)
    
    def register_user(
        self,
        email: str,
        password: str,
        attributes: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Registrar un nuevo usuario en el User Pool.
        
        Args:
            email: Email del usuario
            password: Contraseña (debe cumplir con la política del User Pool)
            attributes: Atributos adicionales del usuario (name, phone_number, etc)
            
        Returns:
            Dict con user_sub y estado de confirmación
            
        Raises:
            ValueError: Si el email o password están vacíos o son inválidos
            ClientError: Si el usuario ya existe o hay otros errores de AWS
        """
        if not email or not password:
            raise ValueError("Email y password son requeridos")
        
        # Preparar parámetros
        params = {
            "ClientId": self.client_id,
            "Username": email,
            "Password": password,
            "UserAttributes": [
                {"Name": "email", "Value": email}
            ]
        }
        
        # Agregar atributos adicionales si se proporcionan
        if attributes:
            for name, value in attributes.items():
                if name != "email":  # Ya lo agregamos arriba
                    params["UserAttributes"].append({"Name": name, "Value": value})
        
        # Agregar SECRET_HASH si es necesario
        secret_hash = self._calculate_secret_hash(email)
        if secret_hash:
            params["SecretHash"] = secret_hash
        
        try:
            response = self.client.sign_up(**params)
            
            return {
                "user_sub": response["UserSub"],
                "confirmation_required": not response["UserConfirmed"],
                "code_delivery_destination": response.get("CodeDeliveryDetails", {})
            }
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            
            if error_code == "UsernameExistsException":
                raise ValueError(f"El usuario {email} ya existe")
            elif error_code == "InvalidPasswordException":
                raise ValueError("La contraseña no cumple con los requisitos de seguridad")
            elif error_code == "InvalidParameterException":
                raise ValueError(f"Parámetros inválidos: {e.response['Error']['Message']}")
            else:
                raise
    
    def confirm_user(self, email: str, code: str) -> Dict[str, Any]:
        """
        Confirmar el registro de un usuario con el código de verificación.
        
        Args:
            email: Email del usuario
            code: Código de verificación recibido por email
            
        Returns:
            Dict con confirmación exitosa
            
        Raises:
            ValueError: Si el código es inválido o expiró
            ClientError: Para otros errores de AWS
        """
        if not email or not code:
            raise ValueError("Email y código son requeridos")
        
        # Preparar parámetros
        params = {
            "ClientId": self.client_id,
            "Username": email,
            "ConfirmationCode": code
        }
        
        # Agregar SECRET_HASH si es necesario
        secret_hash = self._calculate_secret_hash(email)
        if secret_hash:
            params["SecretHash"] = secret_hash
        
        try:
            self.client.confirm_sign_up(**params)
            return {"message": "Usuario confirmado exitosamente"}
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            
            if error_code == "CodeMismatchException":
                raise ValueError("Código de verificación incorrecto")
            elif error_code == "ExpiredCodeException":
                raise ValueError("El código de verificación ha expirado")
            elif error_code == "NotAuthorizedException":
                raise ValueError("Usuario ya confirmado o no autorizado")
            else:
                raise
    
    def authenticate_user(self, email: str, password: str) -> Dict[str, Any]:
        """
        Autenticar un usuario y obtener tokens JWT.
        
        Args:
            email: Email del usuario
            password: Contraseña del usuario
            
        Returns:
            Dict con access_token, id_token, refresh_token y expires_in
            
        Raises:
            ValueError: Si las credenciales son inválidas
            ClientError: Para otros errores de AWS
        """
        if not email or not password:
            raise ValueError("Email y password son requeridos")
        
        # Preparar parámetros de autenticación
        auth_params = {
            "USERNAME": email,
            "PASSWORD": password
        }
        
        # Agregar SECRET_HASH si es necesario
        secret_hash = self._calculate_secret_hash(email)
        if secret_hash:
            auth_params["SECRET_HASH"] = secret_hash
        
        params = {
            "ClientId": self.client_id,
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": auth_params
        }
        
        try:
            response = self.client.initiate_auth(**params)
            
            # Manejar desafíos de autenticación si los hay
            if "ChallengeName" in response:
                raise ValueError(f"Autenticación requiere desafío: {response['ChallengeName']}")
            
            result = response["AuthenticationResult"]
            
            return {
                "access_token": result["AccessToken"],
                "id_token": result["IdToken"],
                "refresh_token": result["RefreshToken"],
                "expires_in": result["ExpiresIn"],
                "token_type": result["TokenType"]
            }
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            
            if error_code == "NotAuthorizedException":
                raise ValueError("Email o contraseña incorrectos")
            elif error_code == "UserNotConfirmedException":
                raise ValueError("El usuario no ha confirmado su email")
            elif error_code == "UserNotFoundException":
                raise ValueError("Usuario no encontrado")
            else:
                raise
    
    def refresh_token(self, refresh_token: str, username: Optional[str] = None) -> Dict[str, Any]:
        """
        Obtener nuevos tokens usando un refresh token.
        
        Args:
            refresh_token: Token de refresh válido
            username: Username/email (requerido si el App Client tiene secret)
            
        Returns:
            Dict con nuevos access_token e id_token
            
        Raises:
            ValueError: Si el refresh token es inválido
            ClientError: Para otros errores de AWS
        """
        if not refresh_token:
            raise ValueError("Refresh token es requerido")
        
        if self.client_secret and not username:
            raise ValueError("Username es requerido cuando el App Client tiene secret")
        
        # Preparar parámetros
        auth_params = {
            "REFRESH_TOKEN": refresh_token
        }
        
        # Agregar SECRET_HASH si es necesario
        if self.client_secret and username:
            auth_params["SECRET_HASH"] = self._calculate_secret_hash(username)
        
        params = {
            "ClientId": self.client_id,
            "AuthFlow": "REFRESH_TOKEN_AUTH",
            "AuthParameters": auth_params
        }
        
        try:
            response = self.client.initiate_auth(**params)
            result = response["AuthenticationResult"]
            
            return {
                "access_token": result["AccessToken"],
                "id_token": result["IdToken"],
                "expires_in": result["ExpiresIn"],
                "token_type": result["TokenType"]
            }
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            
            if error_code == "NotAuthorizedException":
                raise ValueError("Refresh token inválido o expirado")
            else:
                raise
    
    def forgot_password(self, email: str) -> Dict[str, Any]:
        """
        Iniciar el proceso de recuperación de contraseña.
        
        Args:
            email: Email del usuario
            
        Returns:
            Dict con información sobre el envío del código
            
        Raises:
            ValueError: Si el email está vacío
            ClientError: Para otros errores de AWS
        """
        if not email:
            raise ValueError("Email es requerido")
        
        # Preparar parámetros
        params = {
            "ClientId": self.client_id,
            "Username": email
        }
        
        # Agregar SECRET_HASH si es necesario
        secret_hash = self._calculate_secret_hash(email)
        if secret_hash:
            params["SecretHash"] = secret_hash
        
        try:
            response = self.client.forgot_password(**params)
            
            return {
                "code_delivery_details": response.get("CodeDeliveryDetails", {}),
                "message": "Código de recuperación enviado"
            }
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            
            if error_code == "UserNotFoundException":
                # Por seguridad, no revelar si el usuario existe
                return {"message": "Si el email existe, se enviará un código de recuperación"}
            elif error_code == "LimitExceededException":
                raise ValueError("Demasiados intentos. Por favor intente más tarde")
            else:
                raise
    
    def confirm_forgot_password(
        self,
        email: str,
        code: str,
        new_password: str
    ) -> Dict[str, Any]:
        """
        Confirmar el cambio de contraseña con el código recibido.
        
        Args:
            email: Email del usuario
            code: Código de verificación recibido
            new_password: Nueva contraseña
            
        Returns:
            Dict con confirmación exitosa
            
        Raises:
            ValueError: Si algún parámetro es inválido
            ClientError: Para otros errores de AWS
        """
        if not email or not code or not new_password:
            raise ValueError("Email, código y nueva contraseña son requeridos")
        
        # Preparar parámetros
        params = {
            "ClientId": self.client_id,
            "Username": email,
            "ConfirmationCode": code,
            "Password": new_password
        }
        
        # Agregar SECRET_HASH si es necesario
        secret_hash = self._calculate_secret_hash(email)
        if secret_hash:
            params["SecretHash"] = secret_hash
        
        try:
            self.client.confirm_forgot_password(**params)
            return {"message": "Contraseña actualizada exitosamente"}
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            
            if error_code == "CodeMismatchException":
                raise ValueError("Código de verificación incorrecto")
            elif error_code == "ExpiredCodeException":
                raise ValueError("El código de verificación ha expirado")
            elif error_code == "InvalidPasswordException":
                raise ValueError("La nueva contraseña no cumple con los requisitos")
            else:
                raise
    
    def get_user(self, access_token: str) -> Dict[str, Any]:
        """
        Obtener información del usuario usando su access token.
        
        Args:
            access_token: Token de acceso válido del usuario
            
        Returns:
            Dict con atributos del usuario
            
        Raises:
            ValueError: Si el token es inválido
            ClientError: Para otros errores de AWS
        """
        if not access_token:
            raise ValueError("Access token es requerido")
        
        try:
            response = self.client.get_user(AccessToken=access_token)
            
            # Convertir atributos a dict
            attributes = {}
            for attr in response["UserAttributes"]:
                attributes[attr["Name"]] = attr["Value"]
            
            return {
                "username": response["Username"],
                "attributes": attributes,
                "mfa_options": response.get("MFAOptions", []),
                "preferred_mfa": response.get("PreferredMfaSetting"),
                "user_mfa_settings": response.get("UserMFASettingList", [])
            }
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            
            if error_code == "NotAuthorizedException":
                raise ValueError("Token de acceso inválido o expirado")
            else:
                raise
    
    def update_user_attributes(
        self,
        access_token: str,
        attributes: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Actualizar atributos del usuario.
        
        Args:
            access_token: Token de acceso válido del usuario
            attributes: Diccionario con los atributos a actualizar
            
        Returns:
            Dict con confirmación de actualización
            
        Raises:
            ValueError: Si no hay atributos o el token es inválido
            ClientError: Para otros errores de AWS
        """
        if not access_token:
            raise ValueError("Access token es requerido")
        
        if not attributes:
            raise ValueError("Debe proporcionar al menos un atributo para actualizar")
        
        # Convertir dict a formato de Cognito
        user_attributes = []
        for name, value in attributes.items():
            user_attributes.append({"Name": name, "Value": value})
        
        try:
            response = self.client.update_user_attributes(
                UserAttributes=user_attributes,
                AccessToken=access_token
            )
            
            # Verificar si algún atributo requiere verificación
            code_delivery_list = response.get("CodeDeliveryDetailsList", [])
            
            return {
                "message": "Atributos actualizados exitosamente",
                "verification_required": code_delivery_list
            }
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            
            if error_code == "NotAuthorizedException":
                raise ValueError("Token de acceso inválido o expirado")
            elif error_code == "InvalidParameterException":
                raise ValueError("Uno o más atributos son inválidos")
            else:
                raise
    
    def delete_user(self, access_token: str) -> Dict[str, Any]:
        """
        Eliminar la cuenta del usuario.
        
        Args:
            access_token: Token de acceso válido del usuario
            
        Returns:
            Dict con confirmación de eliminación
            
        Raises:
            ValueError: Si el token es inválido
            ClientError: Para otros errores de AWS
        """
        if not access_token:
            raise ValueError("Access token es requerido")
        
        try:
            self.client.delete_user(AccessToken=access_token)
            return {"message": "Usuario eliminado exitosamente"}
            
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            
            if error_code == "NotAuthorizedException":
                raise ValueError("Token de acceso inválido o expirado")
            else:
                raise
    
    def close(self):
        """
        Cerrar el cliente y limpiar recursos.
        
        Es recomendable llamar este método cuando ya no se necesite el manager,
        o usar el manager con un context manager que lo hará automáticamente.
        """
        if self._client:
            # boto3 clients don't have a close method, but we can clean references
            self._client = None
        if self._session:
            self._session = None
    
    def __enter__(self):
        """Context manager support - retorna self al entrar."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager support - cierra recursos al salir."""
        self.close()
        return False  # No suprimir excepciones