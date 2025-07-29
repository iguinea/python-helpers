"""
Utilidades SQS para AWS

Este módulo proporciona funciones helper para interactuar con Amazon Simple Queue Service (SQS),
permitiendo enviar, recibir y gestionar mensajes en colas SQS.
"""

import json
import os
from typing import Optional, Dict, Any, List, Union, Tuple
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def _get_sqs_client(region_name: Optional[str] = None):
    """
    Crear un cliente SQS reutilizable.
    
    Args:
        region_name: Región AWS donde está la cola (por defecto: desde el entorno)
        
    Returns:
        boto3.client: Cliente SQS configurado
        
    Raises:
        NoCredentialsError: Si las credenciales AWS no están configuradas
    """
    if not region_name:
        region_name = os.environ.get("AWS_DEFAULT_REGION", "eu-west-1")
    
    try:
        session = boto3.Session()
        return session.client(service_name="sqs", region_name=region_name)
    except NoCredentialsError:
        raise NoCredentialsError()


def send_message(
    queue_url: str,
    message_body: Union[str, Dict[str, Any]],
    message_attributes: Optional[Dict[str, Dict[str, Any]]] = None,
    delay_seconds: int = 0,
    message_group_id: Optional[str] = None,
    message_deduplication_id: Optional[str] = None,
    region_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enviar un mensaje a una cola SQS.
    
    Args:
        queue_url: URL de la cola SQS
        message_body: Cuerpo del mensaje (string o dict que se convertirá a JSON)
        message_attributes: Atributos del mensaje (metadatos adicionales)
        delay_seconds: Segundos de retraso antes de que el mensaje esté disponible (0-900)
        message_group_id: ID del grupo de mensajes (solo para colas FIFO)
        message_deduplication_id: ID de deduplicación (solo para colas FIFO)
        region_name: Región AWS donde está la cola
        
    Returns:
        Dict con MessageId, MD5OfMessageBody y otros metadatos del mensaje enviado
        
    Raises:
        ValueError: Si los parámetros son inválidos
        ClientError: Si hay un error de AWS
        
    Ejemplos:
        >>> # Enviar mensaje simple
        >>> response = send_message(
        ...     "https://sqs.eu-west-1.amazonaws.com/123456789/mi-cola",
        ...     "Hola mundo"
        ... )
        
        >>> # Enviar mensaje con atributos
        >>> response = send_message(
        ...     queue_url,
        ...     {"tipo": "pedido", "id": 123},
        ...     message_attributes={
        ...         "prioridad": {"DataType": "String", "StringValue": "alta"}
        ...     }
        ... )
    """
    client = _get_sqs_client(region_name)
    
    # Convertir dict a JSON si es necesario
    if isinstance(message_body, dict):
        message_body = json.dumps(message_body, ensure_ascii=False)
    
    # Validar delay_seconds
    if not 0 <= delay_seconds <= 900:
        raise ValueError("delay_seconds debe estar entre 0 y 900")
    
    # Preparar parámetros
    params = {
        "QueueUrl": queue_url,
        "MessageBody": message_body,
        "DelaySeconds": delay_seconds,
    }
    
    if message_attributes:
        params["MessageAttributes"] = message_attributes
    
    # Parámetros para colas FIFO
    if message_group_id:
        params["MessageGroupId"] = message_group_id
    if message_deduplication_id:
        params["MessageDeduplicationId"] = message_deduplication_id
    
    try:
        response = client.send_message(**params)
        return response
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "QueueDoesNotExist":
            raise ValueError(f"La cola no existe: {queue_url}")
        elif error_code == "InvalidMessageContents":
            raise ValueError("El contenido del mensaje es inválido")
        elif error_code == "AccessDenied":
            raise PermissionError(
                f"Acceso denegado a la cola {queue_url}. Verifica los permisos IAM para sqs:SendMessage"
            )
        else:
            raise


def send_message_batch(
    queue_url: str,
    entries: List[Dict[str, Any]],
    region_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enviar múltiples mensajes a una cola SQS en lote (máximo 10).
    
    Args:
        queue_url: URL de la cola SQS
        entries: Lista de mensajes a enviar (máximo 10). Cada entrada debe tener:
                - Id: Identificador único del mensaje en el lote
                - MessageBody: Cuerpo del mensaje
                - DelaySeconds (opcional): Retraso en segundos
                - MessageAttributes (opcional): Atributos del mensaje
                - MessageGroupId (opcional): Para colas FIFO
                - MessageDeduplicationId (opcional): Para colas FIFO
        region_name: Región AWS donde está la cola
        
    Returns:
        Dict con Successful (mensajes enviados) y Failed (mensajes fallidos)
        
    Raises:
        ValueError: Si hay más de 10 mensajes o parámetros inválidos
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> messages = [
        ...     {"Id": "1", "MessageBody": "Mensaje 1"},
        ...     {"Id": "2", "MessageBody": json.dumps({"tipo": "pedido"}), "DelaySeconds": 5}
        ... ]
        >>> response = send_message_batch(queue_url, messages)
        >>> print(f"Enviados: {len(response['Successful'])}")
    """
    if len(entries) > 10:
        raise ValueError("No se pueden enviar más de 10 mensajes por lote")
    
    if not entries:
        raise ValueError("La lista de mensajes no puede estar vacía")
    
    client = _get_sqs_client(region_name)
    
    # Convertir dicts a JSON en MessageBody si es necesario
    for entry in entries:
        if isinstance(entry.get("MessageBody"), dict):
            entry["MessageBody"] = json.dumps(entry["MessageBody"], ensure_ascii=False)
    
    try:
        response = client.send_message_batch(
            QueueUrl=queue_url,
            Entries=entries
        )
        return response
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "QueueDoesNotExist":
            raise ValueError(f"La cola no existe: {queue_url}")
        elif error_code == "BatchRequestTooLong":
            raise ValueError("El tamaño total del lote excede el límite permitido")
        else:
            raise


def receive_messages(
    queue_url: str,
    max_messages: int = 1,
    wait_time_seconds: int = 0,
    visibility_timeout: Optional[int] = None,
    message_attribute_names: Optional[List[str]] = None,
    attribute_names: Optional[List[str]] = None,
    region_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Recibir mensajes de una cola SQS.
    
    Args:
        queue_url: URL de la cola SQS
        max_messages: Número máximo de mensajes a recibir (1-10)
        wait_time_seconds: Tiempo de espera para long polling (0-20 segundos)
        visibility_timeout: Tiempo en segundos que el mensaje estará invisible para otros consumidores
        message_attribute_names: Lista de nombres de atributos de mensaje a incluir
                                (usar ['All'] para todos)
        attribute_names: Lista de atributos del mensaje a incluir 
                        (ej: ['All'], ['ApproximateReceiveCount'])
        region_name: Región AWS donde está la cola
        
    Returns:
        Lista de mensajes recibidos. Cada mensaje incluye:
        - MessageId: ID único del mensaje
        - ReceiptHandle: Handle para eliminar el mensaje
        - Body: Cuerpo del mensaje
        - Attributes: Atributos del mensaje (si se solicitaron)
        - MessageAttributes: Atributos personalizados (si se solicitaron)
        
    Raises:
        ValueError: Si los parámetros son inválidos
        ClientError: Si hay un error de AWS
        
    Ejemplos:
        >>> # Recibir un mensaje con espera corta
        >>> messages = receive_messages(queue_url, wait_time_seconds=5)
        >>> for msg in messages:
        ...     print(msg['Body'])
        ...     # Procesar mensaje...
        ...     delete_message(queue_url, msg['ReceiptHandle'])
        
        >>> # Recibir múltiples mensajes con atributos
        >>> messages = receive_messages(
        ...     queue_url,
        ...     max_messages=10,
        ...     attribute_names=['All'],
        ...     message_attribute_names=['All']
        ... )
    """
    if not 1 <= max_messages <= 10:
        raise ValueError("max_messages debe estar entre 1 y 10")
    
    if not 0 <= wait_time_seconds <= 20:
        raise ValueError("wait_time_seconds debe estar entre 0 y 20")
    
    client = _get_sqs_client(region_name)
    
    # Preparar parámetros
    params = {
        "QueueUrl": queue_url,
        "MaxNumberOfMessages": max_messages,
        "WaitTimeSeconds": wait_time_seconds,
    }
    
    if visibility_timeout is not None:
        if not 0 <= visibility_timeout <= 43200:  # 12 horas
            raise ValueError("visibility_timeout debe estar entre 0 y 43200 segundos")
        params["VisibilityTimeout"] = visibility_timeout
    
    if message_attribute_names:
        params["MessageAttributeNames"] = message_attribute_names
    
    if attribute_names:
        params["AttributeNames"] = attribute_names
    
    try:
        response = client.receive_message(**params)
        return response.get("Messages", [])
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "QueueDoesNotExist":
            raise ValueError(f"La cola no existe: {queue_url}")
        elif error_code == "AccessDenied":
            raise PermissionError(
                f"Acceso denegado a la cola {queue_url}. Verifica los permisos IAM para sqs:ReceiveMessage"
            )
        else:
            raise


def delete_message(
    queue_url: str,
    receipt_handle: str,
    region_name: Optional[str] = None,
) -> None:
    """
    Eliminar un mensaje de la cola SQS.
    
    Args:
        queue_url: URL de la cola SQS
        receipt_handle: Receipt handle del mensaje a eliminar
        region_name: Región AWS donde está la cola
        
    Raises:
        ValueError: Si los parámetros son inválidos
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> messages = receive_messages(queue_url)
        >>> for msg in messages:
        ...     # Procesar mensaje
        ...     delete_message(queue_url, msg['ReceiptHandle'])
    """
    if not receipt_handle:
        raise ValueError("receipt_handle no puede estar vacío")
    
    client = _get_sqs_client(region_name)
    
    try:
        client.delete_message(
            QueueUrl=queue_url,
            ReceiptHandle=receipt_handle
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "QueueDoesNotExist":
            raise ValueError(f"La cola no existe: {queue_url}")
        elif error_code == "ReceiptHandleIsInvalid":
            raise ValueError("El receipt handle es inválido o ha expirado")
        elif error_code == "AccessDenied":
            raise PermissionError(
                f"Acceso denegado a la cola {queue_url}. Verifica los permisos IAM para sqs:DeleteMessage"
            )
        else:
            raise


def delete_message_batch(
    queue_url: str,
    entries: List[Dict[str, str]],
    region_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Eliminar múltiples mensajes de la cola SQS en lote (máximo 10).
    
    Args:
        queue_url: URL de la cola SQS
        entries: Lista de mensajes a eliminar. Cada entrada debe tener:
                - Id: Identificador único en el lote
                - ReceiptHandle: Receipt handle del mensaje
        region_name: Región AWS donde está la cola
        
    Returns:
        Dict con Successful (mensajes eliminados) y Failed (mensajes fallidos)
        
    Raises:
        ValueError: Si hay más de 10 mensajes o parámetros inválidos
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> entries = [
        ...     {"Id": "1", "ReceiptHandle": receipt1},
        ...     {"Id": "2", "ReceiptHandle": receipt2}
        ... ]
        >>> response = delete_message_batch(queue_url, entries)
        >>> if response.get('Failed'):
        ...     print(f"Fallos: {len(response['Failed'])}")
    """
    if len(entries) > 10:
        raise ValueError("No se pueden eliminar más de 10 mensajes por lote")
    
    if not entries:
        raise ValueError("La lista de mensajes no puede estar vacía")
    
    client = _get_sqs_client(region_name)
    
    try:
        response = client.delete_message_batch(
            QueueUrl=queue_url,
            Entries=entries
        )
        return response
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "QueueDoesNotExist":
            raise ValueError(f"La cola no existe: {queue_url}")
        else:
            raise


def get_queue_attributes(
    queue_url: str,
    attribute_names: Optional[List[str]] = None,
    region_name: Optional[str] = None,
) -> Dict[str, str]:
    """
    Obtener atributos de una cola SQS.
    
    Args:
        queue_url: URL de la cola SQS
        attribute_names: Lista de atributos a obtener (por defecto: ['All'])
                        Atributos disponibles:
                        - ApproximateNumberOfMessages
                        - ApproximateNumberOfMessagesNotVisible
                        - CreatedTimestamp
                        - DelaySeconds
                        - LastModifiedTimestamp
                        - MaximumMessageSize
                        - MessageRetentionPeriod
                        - QueueArn
                        - ReceiveMessageWaitTimeSeconds
                        - VisibilityTimeout
                        - FifoQueue
                        - ContentBasedDeduplication
        region_name: Región AWS donde está la cola
        
    Returns:
        Dict con los atributos solicitados
        
    Raises:
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> # Obtener todos los atributos
        >>> attrs = get_queue_attributes(queue_url)
        >>> print(f"Mensajes en cola: {attrs['ApproximateNumberOfMessages']}")
        
        >>> # Obtener atributos específicos
        >>> attrs = get_queue_attributes(
        ...     queue_url,
        ...     ['ApproximateNumberOfMessages', 'VisibilityTimeout']
        ... )
    """
    if attribute_names is None:
        attribute_names = ['All']
    
    client = _get_sqs_client(region_name)
    
    try:
        response = client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=attribute_names
        )
        return response.get('Attributes', {})
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "QueueDoesNotExist":
            raise ValueError(f"La cola no existe: {queue_url}")
        elif error_code == "AccessDenied":
            raise PermissionError(
                f"Acceso denegado a la cola {queue_url}. Verifica los permisos IAM para sqs:GetQueueAttributes"
            )
        else:
            raise


def purge_queue(
    queue_url: str,
    region_name: Optional[str] = None,
) -> None:
    """
    Vaciar completamente una cola SQS (eliminar todos los mensajes).
    
    ADVERTENCIA: Esta operación es irreversible y eliminará TODOS los mensajes.
    Solo se puede purgar una cola cada 60 segundos.
    
    Args:
        queue_url: URL de la cola SQS
        region_name: Región AWS donde está la cola
        
    Raises:
        ClientError: Si hay un error de AWS
        
    Ejemplo:
        >>> # Vaciar una cola (¡usar con precaución!)
        >>> purge_queue(queue_url)
    """
    client = _get_sqs_client(region_name)
    
    try:
        client.purge_queue(QueueUrl=queue_url)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "QueueDoesNotExist":
            raise ValueError(f"La cola no existe: {queue_url}")
        elif error_code == "PurgeQueueInProgress":
            raise ValueError("Ya hay una purga en progreso. Espera 60 segundos.")
        elif error_code == "AccessDenied":
            raise PermissionError(
                f"Acceso denegado a la cola {queue_url}. Verifica los permisos IAM para sqs:PurgeQueue"
            )
        else:
            raise


def check_sqs_connection(region_name: Optional[str] = None) -> bool:
    """
    Verificar si SQS es accesible.
    
    Args:
        region_name: Región AWS para probar (opcional)
        
    Returns:
        bool: True si la conexión es exitosa, False en caso contrario
    """
    try:
        client = _get_sqs_client(region_name)
        # Listar colas (con límite 1) para probar la conexión
        client.list_queues(MaxResults=1)
        return True
    except Exception as e:
        print(f"Prueba de conexión SQS falló: {e}")
        return False