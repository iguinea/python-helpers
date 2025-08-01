"""
Utilidades SNS para AWS

Este módulo proporciona funciones helper para interactuar con Amazon Simple Notification Service (SNS),
permitiendo publicar mensajes a tópicos, suscribir endpoints y gestionar notificaciones.
"""

import json
import os
from typing import Optional, Dict, Any, List, Union
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def _get_sns_client(region_name: Optional[str] = None):
    """
    Crear un cliente SNS reutilizable.
    
    Args:
        region_name: Región AWS donde está el servicio (por defecto: desde el entorno)
        
    Returns:
        boto3.client: Cliente SNS configurado
        
    Raises:
        NoCredentialsError: Si las credenciales AWS no están configuradas
    """
    if not region_name:
        region_name = os.environ.get("AWS_DEFAULT_REGION", "eu-west-1")
    
    try:
        session = boto3.Session()
        return session.client(service_name="sns", region_name=region_name)
    except NoCredentialsError:
        raise NoCredentialsError()


def publish_message(
    topic_arn: Optional[str] = None,
    phone_number: Optional[str] = None,
    message: Union[str, Dict[str, Any]] = None,
    subject: Optional[str] = None,
    message_attributes: Optional[Dict[str, Dict[str, Any]]] = None,
    message_structure: Optional[str] = None,
    message_deduplication_id: Optional[str] = None,
    message_group_id: Optional[str] = None,
    region_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Publicar un mensaje a un tópico SNS o directamente a un número de teléfono.
    
    Args:
        topic_arn: ARN del tópico SNS (requerido si no se proporciona phone_number)
        phone_number: Número de teléfono para SMS directo (requerido si no se proporciona topic_arn)
        message: Contenido del mensaje (string o dict que se convertirá a JSON)
        subject: Asunto del mensaje (usado en notificaciones por email)
        message_attributes: Atributos del mensaje para filtrado
        message_structure: "json" para mensajes con formato específico por protocolo
        message_deduplication_id: ID de deduplicación (solo para tópicos FIFO)
        message_group_id: ID del grupo de mensajes (solo para tópicos FIFO)
        region_name: Región AWS donde está el servicio
        
    Returns:
        Dict con MessageId y SequenceNumber (para FIFO)
        
    Raises:
        ValueError: Si los parámetros son inválidos
        ClientError: Si hay un error de AWS
        
    Ejemplos:
        >>> # Publicar a un tópico
        >>> response = publish_message(
        ...     topic_arn="arn:aws:sns:eu-west-1:123456789:mi-topico",
        ...     message="Notificación importante",
        ...     subject="Alerta del sistema"
        ... )
        
        >>> # Enviar SMS directo
        >>> response = publish_message(
        ...     phone_number="+34600123456",
        ...     message="Código de verificación: 1234"
        ... )
        
        >>> # Mensaje con estructura JSON para diferentes protocolos
        >>> message_json = {
        ...     "default": "Mensaje por defecto",
        ...     "email": "Contenido detallado para email",
        ...     "sms": "Mensaje corto para SMS"
        ... }
        >>> response = publish_message(
        ...     topic_arn=topic_arn,
        ...     message=json.dumps(message_json),
        ...     message_structure="json"
        ... )
    """
    # Validar que se proporcione topic_arn o phone_number
    if not topic_arn and not phone_number:
        raise ValueError("Debe proporcionar topic_arn o phone_number")
    
    if topic_arn and phone_number:
        raise ValueError("Proporcione solo uno: topic_arn o phone_number")
    
    if not message:
        raise ValueError("El mensaje no puede estar vacío")
    
    client = _get_sns_client(region_name)
    
    # Convertir dict a JSON si es necesario
    if isinstance(message, dict):
        message = json.dumps(message, ensure_ascii=False)
    
    # Preparar parámetros
    params = {
        "Message": message,
    }
    
    if topic_arn:
        params["TopicArn"] = topic_arn
    if phone_number:
        params["PhoneNumber"] = phone_number
    if subject:
        params["Subject"] = subject
    if message_attributes:
        params["MessageAttributes"] = message_attributes
    if message_structure:
        params["MessageStructure"] = message_structure
    
    # Parámetros para tópicos FIFO
    if message_group_id:
        params["MessageGroupId"] = message_group_id
    if message_deduplication_id:
        params["MessageDeduplicationId"] = message_deduplication_id
    
    try:
        response = client.publish(**params)
        return response
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFound":
            raise ValueError(f"El tópico no existe: {topic_arn}")
        elif error_code == "InvalidParameter":
            raise ValueError(f"Parámetro inválido: {e}")
        elif error_code == "AuthorizationError":
            raise PermissionError(
                f"Acceso denegado al tópico {topic_arn}. Verifica los permisos IAM para sns:Publish"
            )
        else:
            raise


def publish_batch(
    topic_arn: str,
    entries: List[Dict[str, Any]],
    region_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Publicar múltiples mensajes a un tópico SNS en lote (máximo 10).
    
    Args:
        topic_arn: ARN del tópico SNS
        entries: Lista de mensajes a publicar (máximo 10). Cada entrada debe tener:
                - Id: Identificador único del mensaje en el lote
                - Message: Contenido del mensaje
                - Subject (opcional): Asunto del mensaje
                - MessageAttributes (opcional): Atributos del mensaje
                - MessageDeduplicationId (opcional): Para tópicos FIFO
                - MessageGroupId (opcional): Para tópicos FIFO
        region_name: Región AWS donde está el servicio
        
    Returns:
        Dict con Successful (mensajes publicados) y Failed (mensajes fallidos)
        
    Raises:
        ValueError: Si hay más de 10 mensajes o parámetros inválidos
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> messages = [
        ...     {"Id": "1", "Message": "Primer mensaje"},
        ...     {"Id": "2", "Message": "Segundo mensaje", "Subject": "Alerta"}
        ... ]
        >>> response = publish_batch(topic_arn, messages)
        >>> print(f"Publicados: {len(response['Successful'])}")
    """
    if len(entries) > 10:
        raise ValueError("No se pueden publicar más de 10 mensajes por lote")
    
    if not entries:
        raise ValueError("La lista de mensajes no puede estar vacía")
    
    client = _get_sns_client(region_name)
    
    # Convertir dicts a JSON en Message si es necesario
    for entry in entries:
        if isinstance(entry.get("Message"), dict):
            entry["Message"] = json.dumps(entry["Message"], ensure_ascii=False)
    
    try:
        response = client.publish_batch(
            TopicArn=topic_arn,
            PublishBatchRequestEntries=entries
        )
        return response
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFound":
            raise ValueError(f"El tópico no existe: {topic_arn}")
        elif error_code == "BatchRequestTooLong":
            raise ValueError("El tamaño total del lote excede el límite permitido")
        else:
            raise


def subscribe(
    topic_arn: str,
    protocol: str,
    endpoint: str,
    attributes: Optional[Dict[str, str]] = None,
    return_subscription_arn: bool = True,
    region_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Suscribir un endpoint a un tópico SNS.
    
    Args:
        topic_arn: ARN del tópico SNS
        protocol: Protocolo de entrega (email, email-json, sms, sqs, lambda, http, https, application)
        endpoint: Endpoint según el protocolo:
                 - email/email-json: dirección de email
                 - sms: número de teléfono
                 - sqs: ARN de la cola SQS
                 - lambda: ARN de la función Lambda
                 - http/https: URL del endpoint
                 - application: ARN del endpoint de aplicación móvil
        attributes: Atributos de la suscripción (ej: FilterPolicy)
        return_subscription_arn: Si devolver el ARN inmediatamente (no aplica para email)
        region_name: Región AWS donde está el servicio
        
    Returns:
        Dict con SubscriptionArn (o "pending confirmation" para email)
        
    Raises:
        ValueError: Si los parámetros son inválidos
        ClientError: Si hay un error de AWS
        
    Ejemplos:
        >>> # Suscribir email
        >>> response = subscribe(
        ...     topic_arn="arn:aws:sns:eu-west-1:123456789:alertas",
        ...     protocol="email",
        ...     endpoint="usuario@ejemplo.com"
        ... )
        
        >>> # Suscribir SQS con filtro
        >>> response = subscribe(
        ...     topic_arn=topic_arn,
        ...     protocol="sqs",
        ...     endpoint=queue_arn,
        ...     attributes={
        ...         "FilterPolicy": json.dumps({"tipo": ["error", "critico"]})
        ...     }
        ... )
    """
    valid_protocols = ["email", "email-json", "sms", "sqs", "lambda", "http", "https", "application"]
    if protocol not in valid_protocols:
        raise ValueError(f"Protocolo inválido. Debe ser uno de: {', '.join(valid_protocols)}")
    
    client = _get_sns_client(region_name)
    
    # Preparar parámetros
    params = {
        "TopicArn": topic_arn,
        "Protocol": protocol,
        "Endpoint": endpoint,
        "ReturnSubscriptionArn": return_subscription_arn,
    }
    
    if attributes:
        params["Attributes"] = attributes
    
    try:
        response = client.subscribe(**params)
        return response
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFound":
            raise ValueError(f"El tópico no existe: {topic_arn}")
        elif error_code == "InvalidParameter":
            raise ValueError(f"Parámetro inválido: {e}")
        elif error_code == "AuthorizationError":
            raise PermissionError(
                f"Acceso denegado al tópico {topic_arn}. Verifica los permisos IAM para sns:Subscribe"
            )
        else:
            raise


def unsubscribe(
    subscription_arn: str,
    region_name: Optional[str] = None,
) -> None:
    """
    Cancelar una suscripción a un tópico SNS.
    
    Args:
        subscription_arn: ARN de la suscripción a cancelar
        region_name: Región AWS donde está el servicio
        
    Raises:
        ValueError: Si el ARN es inválido
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> unsubscribe("arn:aws:sns:eu-west-1:123456789:mi-topico:abc123")
    """
    if not subscription_arn or subscription_arn == "pending confirmation":
        raise ValueError("ARN de suscripción inválido")
    
    client = _get_sns_client(region_name)
    
    try:
        client.unsubscribe(SubscriptionArn=subscription_arn)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFound":
            raise ValueError(f"La suscripción no existe: {subscription_arn}")
        elif error_code == "AuthorizationError":
            raise PermissionError(
                f"Acceso denegado a la suscripción {subscription_arn}. Verifica los permisos IAM para sns:Unsubscribe"
            )
        else:
            raise


def list_subscriptions_by_topic(
    topic_arn: str,
    next_token: Optional[str] = None,
    region_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Listar todas las suscripciones de un tópico SNS.
    
    Args:
        topic_arn: ARN del tópico SNS
        next_token: Token para paginación (de llamadas anteriores)
        region_name: Región AWS donde está el servicio
        
    Returns:
        Dict con Subscriptions (lista) y NextToken (si hay más resultados)
        
    Raises:
        ValueError: Si el tópico no existe
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> result = list_subscriptions_by_topic(topic_arn)
        >>> for sub in result['Subscriptions']:
        ...     print(f"{sub['Protocol']}: {sub['Endpoint']}")
    """
    client = _get_sns_client(region_name)
    
    params = {
        "TopicArn": topic_arn,
    }
    
    if next_token:
        params["NextToken"] = next_token
    
    try:
        response = client.list_subscriptions_by_topic(**params)
        return response
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFound":
            raise ValueError(f"El tópico no existe: {topic_arn}")
        elif error_code == "AuthorizationError":
            raise PermissionError(
                f"Acceso denegado al tópico {topic_arn}. Verifica los permisos IAM para sns:ListSubscriptionsByTopic"
            )
        else:
            raise


def get_topic_attributes(
    topic_arn: str,
    region_name: Optional[str] = None,
) -> Dict[str, str]:
    """
    Obtener atributos de un tópico SNS.
    
    Args:
        topic_arn: ARN del tópico SNS
        region_name: Región AWS donde está el servicio
        
    Returns:
        Dict con los atributos del tópico:
        - DisplayName: Nombre para mostrar
        - SubscriptionsConfirmed: Número de suscripciones confirmadas
        - SubscriptionsPending: Número de suscripciones pendientes
        - SubscriptionsDeleted: Número de suscripciones eliminadas
        - DeliveryPolicy: Política de entrega
        - EffectiveDeliveryPolicy: Política de entrega efectiva
        - Policy: Política de acceso
        - Owner: ID de cuenta AWS del propietario
        - KmsMasterKeyId: ID de la clave KMS para cifrado
        - FifoTopic: "true" si es un tópico FIFO
        - ContentBasedDeduplication: "true" si tiene deduplicación basada en contenido
        
    Raises:
        ValueError: Si el tópico no existe
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> attrs = get_topic_attributes(topic_arn)
        >>> print(f"Suscripciones confirmadas: {attrs['SubscriptionsConfirmed']}")
    """
    client = _get_sns_client(region_name)
    
    try:
        response = client.get_topic_attributes(TopicArn=topic_arn)
        return response.get('Attributes', {})
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFound":
            raise ValueError(f"El tópico no existe: {topic_arn}")
        elif error_code == "AuthorizationError":
            raise PermissionError(
                f"Acceso denegado al tópico {topic_arn}. Verifica los permisos IAM para sns:GetTopicAttributes"
            )
        else:
            raise


def set_subscription_attributes(
    subscription_arn: str,
    attribute_name: str,
    attribute_value: str,
    region_name: Optional[str] = None,
) -> None:
    """
    Configurar atributos de una suscripción SNS.
    
    Args:
        subscription_arn: ARN de la suscripción
        attribute_name: Nombre del atributo a configurar:
                       - DeliveryPolicy: Política de reintentos
                       - FilterPolicy: Política de filtrado de mensajes
                       - RawMessageDelivery: "true" para entregar mensajes sin formato SNS
                       - RedrivePolicy: Política de DLQ para endpoints fallidos
        attribute_value: Valor del atributo (string o JSON como string)
        region_name: Región AWS donde está el servicio
        
    Raises:
        ValueError: Si los parámetros son inválidos
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> # Configurar filtro de mensajes
        >>> filter_policy = {
        ...     "tipo": ["pedido", "factura"],
        ...     "prioridad": [{"numeric": [">=", 5]}]
        ... }
        >>> set_subscription_attributes(
        ...     subscription_arn,
        ...     "FilterPolicy",
        ...     json.dumps(filter_policy)
        ... )
    """
    valid_attributes = ["DeliveryPolicy", "FilterPolicy", "RawMessageDelivery", "RedrivePolicy"]
    if attribute_name not in valid_attributes:
        raise ValueError(f"Atributo inválido. Debe ser uno de: {', '.join(valid_attributes)}")
    
    client = _get_sns_client(region_name)
    
    try:
        client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName=attribute_name,
            AttributeValue=attribute_value
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFound":
            raise ValueError(f"La suscripción no existe: {subscription_arn}")
        elif error_code == "InvalidParameter":
            raise ValueError(f"Valor de atributo inválido: {e}")
        elif error_code == "AuthorizationError":
            raise PermissionError(
                f"Acceso denegado a la suscripción {subscription_arn}. Verifica los permisos IAM"
            )
        else:
            raise


def confirm_subscription(
    topic_arn: str,
    token: str,
    authenticate_on_unsubscribe: bool = False,
    region_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Confirmar una suscripción pendiente usando el token recibido.
    
    Args:
        topic_arn: ARN del tópico SNS
        token: Token de confirmación recibido en el mensaje de confirmación
        authenticate_on_unsubscribe: Si requerir autenticación para cancelar suscripción
        region_name: Región AWS donde está el servicio
        
    Returns:
        Dict con SubscriptionArn de la suscripción confirmada
        
    Raises:
        ValueError: Si los parámetros son inválidos
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> # Confirmar suscripción con token recibido por email
        >>> response = confirm_subscription(
        ...     topic_arn,
        ...     "abc123def456..."  # Token del email de confirmación
        ... )
    """
    client = _get_sns_client(region_name)
    
    try:
        response = client.confirm_subscription(
            TopicArn=topic_arn,
            Token=token,
            AuthenticateOnUnsubscribe=str(authenticate_on_unsubscribe).lower()
        )
        return response
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFound":
            raise ValueError(f"El tópico no existe: {topic_arn}")
        elif error_code == "InvalidParameter":
            raise ValueError("Token inválido o expirado")
        elif error_code == "AuthorizationError":
            raise PermissionError(
                f"Acceso denegado al tópico {topic_arn}. Verifica los permisos IAM"
            )
        else:
            raise


def check_sns_connection(region_name: Optional[str] = None) -> bool:
    """
    Verificar si SNS es accesible.
    
    Args:
        region_name: Región AWS para probar (opcional)
        
    Returns:
        bool: True si la conexión es exitosa, False en caso contrario
    """
    try:
        client = _get_sns_client(region_name)
        # Listar tópicos (con límite 1) para probar la conexión
        client.list_topics(MaxResults=1)
        return True
    except Exception as e:
        print(f"Prueba de conexión SNS falló: {e}")
        return False