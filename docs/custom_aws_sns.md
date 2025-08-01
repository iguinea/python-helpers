# Amazon SNS Module

## Descripción General

El módulo `custom_aws.sns` proporciona utilidades para interactuar con Amazon Simple Notification Service (SNS), permitiendo publicar mensajes a tópicos, gestionar suscripciones, enviar SMS directos y manejar notificaciones push.

## Instalación

```python
from custom_aws.sns import (
    publish_message,
    publish_batch,
    subscribe,
    unsubscribe,
    list_subscriptions_by_topic,
    get_topic_attributes,
    set_subscription_attributes,
    confirm_subscription,
    check_sns_connection
)
```

## Funciones Disponibles

### publish_message

Publica un mensaje a un tópico SNS o envía un SMS directo.

```python
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
) -> Dict[str, Any]
```

**Parámetros:**
- `topic_arn`: ARN del tópico SNS (requerido si no se proporciona phone_number)
- `phone_number`: Número de teléfono para SMS directo (requerido si no se proporciona topic_arn)
- `message`: Contenido del mensaje (string o dict que se convertirá a JSON)
- `subject`: Asunto del mensaje (usado en notificaciones por email)
- `message_attributes`: Atributos del mensaje para filtrado
- `message_structure`: "json" para mensajes con formato específico por protocolo
- `message_deduplication_id`: ID de deduplicación (solo para tópicos FIFO)
- `message_group_id`: ID del grupo de mensajes (solo para tópicos FIFO)
- `region_name`: Región AWS donde está el servicio

**Retorna:**
- Dict con MessageId y SequenceNumber (para FIFO)

**Excepciones:**
- `ValueError`: Si los parámetros son inválidos
- `PermissionError`: Si no hay permisos para publicar
- `ClientError`: Para otros errores de AWS

### publish_batch

Publica múltiples mensajes a un tópico SNS en lote (máximo 10).

```python
def publish_batch(
    topic_arn: str,
    entries: List[Dict[str, Any]],
    region_name: Optional[str] = None,
) -> Dict[str, Any]
```

**Parámetros:**
- `topic_arn`: ARN del tópico SNS
- `entries`: Lista de mensajes a publicar (máximo 10)
- `region_name`: Región AWS donde está el servicio

**Estructura de cada entrada:**
```python
{
    "Id": "1",                    # Identificador único en el lote
    "Message": "Contenido",       # Mensaje (string o dict)
    "Subject": "Asunto",          # Opcional
    "MessageAttributes": {...},    # Opcional
    "MessageDeduplicationId": "", # Opcional, para FIFO
    "MessageGroupId": ""          # Opcional, para FIFO
}
```

### subscribe

Suscribe un endpoint a un tópico SNS.

```python
def subscribe(
    topic_arn: str,
    protocol: str,
    endpoint: str,
    attributes: Optional[Dict[str, str]] = None,
    return_subscription_arn: bool = True,
    region_name: Optional[str] = None,
) -> Dict[str, Any]
```

**Parámetros:**
- `topic_arn`: ARN del tópico SNS
- `protocol`: Protocolo de entrega (email, email-json, sms, sqs, lambda, http, https, application)
- `endpoint`: Endpoint según el protocolo
- `attributes`: Atributos de la suscripción (ej: FilterPolicy)
- `return_subscription_arn`: Si devolver el ARN inmediatamente
- `region_name`: Región AWS donde está el servicio

**Protocolos y endpoints:**
- `email`/`email-json`: dirección de email
- `sms`: número de teléfono
- `sqs`: ARN de la cola SQS
- `lambda`: ARN de la función Lambda
- `http`/`https`: URL del endpoint
- `application`: ARN del endpoint de aplicación móvil

### unsubscribe

Cancela una suscripción a un tópico SNS.

```python
def unsubscribe(
    subscription_arn: str,
    region_name: Optional[str] = None,
) -> None
```

### list_subscriptions_by_topic

Lista todas las suscripciones de un tópico SNS.

```python
def list_subscriptions_by_topic(
    topic_arn: str,
    next_token: Optional[str] = None,
    region_name: Optional[str] = None,
) -> Dict[str, Any]
```

**Retorna:**
- Dict con `Subscriptions` (lista) y `NextToken` (si hay más resultados)

### get_topic_attributes

Obtiene atributos de un tópico SNS.

```python
def get_topic_attributes(
    topic_arn: str,
    region_name: Optional[str] = None,
) -> Dict[str, str]
```

**Atributos disponibles:**
- `DisplayName`: Nombre para mostrar
- `SubscriptionsConfirmed`: Número de suscripciones confirmadas
- `SubscriptionsPending`: Número de suscripciones pendientes
- `SubscriptionsDeleted`: Número de suscripciones eliminadas
- `DeliveryPolicy`: Política de entrega
- `Policy`: Política de acceso
- `Owner`: ID de cuenta AWS del propietario
- `KmsMasterKeyId`: ID de la clave KMS para cifrado
- `FifoTopic`: "true" si es un tópico FIFO
- `ContentBasedDeduplication`: "true" si tiene deduplicación basada en contenido

### set_subscription_attributes

Configura atributos de una suscripción SNS.

```python
def set_subscription_attributes(
    subscription_arn: str,
    attribute_name: str,
    attribute_value: str,
    region_name: Optional[str] = None,
) -> None
```

**Atributos configurables:**
- `DeliveryPolicy`: Política de reintentos
- `FilterPolicy`: Política de filtrado de mensajes
- `RawMessageDelivery`: "true" para entregar mensajes sin formato SNS
- `RedrivePolicy`: Política de DLQ para endpoints fallidos

### confirm_subscription

Confirma una suscripción pendiente usando el token recibido.

```python
def confirm_subscription(
    topic_arn: str,
    token: str,
    authenticate_on_unsubscribe: bool = False,
    region_name: Optional[str] = None,
) -> Dict[str, Any]
```

### check_sns_connection

Verifica si SNS es accesible.

```python
def check_sns_connection(
    region_name: Optional[str] = None
) -> bool
```

## Configuración de AWS

### Permisos IAM Requeridos

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sns:Publish",
                "sns:PublishBatch",
                "sns:Subscribe",
                "sns:Unsubscribe",
                "sns:ListSubscriptionsByTopic",
                "sns:GetTopicAttributes",
                "sns:SetSubscriptionAttributes",
                "sns:ConfirmSubscription",
                "sns:ListTopics"
            ],
            "Resource": "*"
        }
    ]
}
```

## Ejemplos de Uso

### Publicar a un Tópico

```python
from custom_aws.sns import publish_message

# Publicar mensaje simple
response = publish_message(
    topic_arn="arn:aws:sns:eu-west-1:123456789:alertas",
    message="Sistema operativo con normalidad",
    subject="Estado del Sistema"
)
print(f"Mensaje publicado: {response['MessageId']}")

# Publicar con atributos para filtrado
response = publish_message(
    topic_arn="arn:aws:sns:eu-west-1:123456789:eventos",
    message={"tipo": "pedido", "id": 12345, "total": 99.50},
    message_attributes={
        "tipo": {"DataType": "String", "StringValue": "pedido"},
        "prioridad": {"DataType": "Number", "StringValue": "1"}
    }
)
```

### Enviar SMS Directo

```python
# Enviar SMS de verificación
response = publish_message(
    phone_number="+34600123456",
    message="Tu código de verificación es: 4532. Válido por 5 minutos."
)
```

### Mensajes con Estructura JSON

```python
import json

# Diferentes mensajes según el protocolo
message_json = {
    "default": "Nueva actualización disponible",
    "email": "Estimado usuario,\n\nHay una nueva actualización disponible para la aplicación.\n\nSaludos,\nEl equipo",
    "sms": "Nueva actualización disponible. Descárgala en app.ejemplo.com",
    "http": json.dumps({
        "version": "2.1.0",
        "features": ["mejora de rendimiento", "nuevos filtros"],
        "url": "https://app.ejemplo.com/update"
    })
}

publish_message(
    topic_arn="arn:aws:sns:eu-west-1:123456789:actualizaciones",
    message=json.dumps(message_json),
    message_structure="json",
    subject="Nueva versión 2.1.0 disponible"
)
```

### Publicar en Lote

```python
from custom_aws.sns import publish_batch

# Preparar múltiples mensajes
messages = [
    {
        "Id": "1",
        "Message": "Primer mensaje del lote",
        "Subject": "Mensaje 1"
    },
    {
        "Id": "2",
        "Message": json.dumps({"tipo": "alerta", "nivel": "info"}),
        "MessageAttributes": {
            "tipo": {"DataType": "String", "StringValue": "alerta"}
        }
    },
    {
        "Id": "3",
        "Message": "Tercer mensaje con retraso",
        "Subject": "Mensaje 3"
    }
]

# Publicar todos de una vez
result = publish_batch(
    "arn:aws:sns:eu-west-1:123456789:notificaciones",
    messages
)

print(f"Mensajes enviados: {len(result['Successful'])}")
if result.get('Failed'):
    print(f"Mensajes fallidos: {len(result['Failed'])}")
    for failed in result['Failed']:
        print(f"  - ID {failed['Id']}: {failed['Message']}")
```

### Gestionar Suscripciones

```python
from custom_aws.sns import subscribe, list_subscriptions_by_topic, unsubscribe

# Suscribir un email
response = subscribe(
    topic_arn="arn:aws:sns:eu-west-1:123456789:newsletter",
    protocol="email",
    endpoint="usuario@ejemplo.com"
)
print(f"Suscripción creada: {response['SubscriptionArn']}")

# Suscribir una cola SQS con filtro
filter_policy = json.dumps({
    "tipo": ["pedido", "factura"],
    "prioridad": [{"numeric": [">=", 5]}]
})

response = subscribe(
    topic_arn="arn:aws:sns:eu-west-1:123456789:eventos",
    protocol="sqs",
    endpoint="arn:aws:sqs:eu-west-1:123456789:cola-prioritaria",
    attributes={"FilterPolicy": filter_policy}
)

# Listar suscripciones
result = list_subscriptions_by_topic(
    "arn:aws:sns:eu-west-1:123456789:eventos"
)

for sub in result['Subscriptions']:
    print(f"{sub['Protocol']}: {sub['Endpoint']} - {sub['SubscriptionArn']}")

# Cancelar suscripción
unsubscribe("arn:aws:sns:eu-west-1:123456789:eventos:sub-12345")
```

### Configurar Filtros de Suscripción

```python
from custom_aws.sns import set_subscription_attributes

# Configurar política de filtrado
filter_policy = {
    "tipo": ["pedido", "devolucion"],
    "tienda": ["MAD01", "BCN02"],
    "importe": [{"numeric": [">", 100]}],
    "urgente": [{"exists": True}]
}

set_subscription_attributes(
    "arn:aws:sns:eu-west-1:123456789:pedidos:sub-12345",
    "FilterPolicy",
    json.dumps(filter_policy)
)

# Activar entrega de mensajes sin formato
set_subscription_attributes(
    "arn:aws:sns:eu-west-1:123456789:eventos:sub-67890",
    "RawMessageDelivery",
    "true"
)
```

### Trabajar con Tópicos FIFO

```python
# Publicar a tópico FIFO
response = publish_message(
    topic_arn="arn:aws:sns:eu-west-1:123456789:pedidos.fifo",
    message={"pedido_id": "ORD-12345", "estado": "procesando"},
    message_group_id="tienda-madrid-01",
    message_deduplication_id="ORD-12345-procesando"
)
print(f"Número de secuencia: {response['SequenceNumber']}")

# Publicar lote a FIFO
messages = [
    {
        "Id": "1",
        "Message": "Pedido creado",
        "MessageGroupId": "cliente-123",
        "MessageDeduplicationId": "pedido-456-creado"
    },
    {
        "Id": "2",
        "Message": "Pedido confirmado",
        "MessageGroupId": "cliente-123",
        "MessageDeduplicationId": "pedido-456-confirmado"
    }
]

publish_batch(
    "arn:aws:sns:eu-west-1:123456789:pedidos.fifo",
    messages
)
```

### Confirmar Suscripción por Email

```python
from custom_aws.sns import confirm_subscription

# Cuando el usuario hace clic en el enlace de confirmación,
# extraer el token y confirmar
token = "2336412f-9b5a-4b6e-b444-8e4b31d4b9e4..."  # Del enlace de confirmación

response = confirm_subscription(
    "arn:aws:sns:eu-west-1:123456789:newsletter",
    token,
    authenticate_on_unsubscribe=True  # Requerir confirmación para desuscribir
)
print(f"Suscripción confirmada: {response['SubscriptionArn']}")
```

### Monitorear Estado del Tópico

```python
from custom_aws.sns import get_topic_attributes

# Obtener información del tópico
attrs = get_topic_attributes("arn:aws:sns:eu-west-1:123456789:alertas")

print(f"Nombre: {attrs.get('DisplayName', 'Sin nombre')}")
print(f"Suscripciones confirmadas: {attrs['SubscriptionsConfirmed']}")
print(f"Suscripciones pendientes: {attrs['SubscriptionsPending']}")
print(f"Propietario: {attrs['Owner']}")
print(f"Tópico FIFO: {'Sí' if attrs.get('FifoTopic') == 'true' else 'No'}")
```

### Manejo de Errores

```python
from custom_aws.sns import publish_message, subscribe
from botocore.exceptions import ClientError, NoCredentialsError

try:
    # Intentar publicar mensaje
    response = publish_message(
        topic_arn="arn:aws:sns:eu-west-1:123456789:alertas",
        message="Mensaje importante"
    )
except NoCredentialsError:
    print("Error: No se encontraron credenciales AWS")
except ValueError as e:
    if "no existe" in str(e):
        print(f"Error: El tópico no existe")
    else:
        print(f"Error de validación: {e}")
except PermissionError as e:
    print(f"Error: Sin permisos - {e}")
except ClientError as e:
    error_code = e.response['Error']['Code']
    if error_code == 'Throttling':
        print("Error: Demasiadas solicitudes, intenta más tarde")
    else:
        print(f"Error de AWS: {e}")
```

### Integración con SQS

```python
from custom_aws.sns import subscribe
from custom_aws.sqs import receive_messages, delete_message

# Suscribir cola SQS a tópico SNS
queue_arn = "arn:aws:sqs:eu-west-1:123456789:procesamiento-pedidos"
topic_arn = "arn:aws:sns:eu-west-1:123456789:pedidos-nuevos"

# Crear suscripción
subscribe(
    topic_arn=topic_arn,
    protocol="sqs",
    endpoint=queue_arn
)

# Procesar mensajes de la cola
queue_url = "https://sqs.eu-west-1.amazonaws.com/123456789/procesamiento-pedidos"

while True:
    messages = receive_messages(queue_url, max_messages=10, wait_time_seconds=20)
    
    for msg in messages:
        try:
            # El mensaje SNS está envuelto en el Body
            sns_message = json.loads(msg['Body'])
            
            # Procesar el mensaje real
            if 'Message' in sns_message:
                data = json.loads(sns_message['Message'])
                print(f"Procesando pedido: {data}")
            
            # Eliminar mensaje de la cola
            delete_message(queue_url, msg['ReceiptHandle'])
            
        except Exception as e:
            print(f"Error procesando mensaje: {e}")
```

## Mejores Prácticas

### 1. Gestión de Tópicos

```python
# Organizar tópicos por ambiente y propósito
topic_patterns = {
    "desarrollo": "arn:aws:sns:region:cuenta:dev-{servicio}-{evento}",
    "produccion": "arn:aws:sns:region:cuenta:prod-{servicio}-{evento}"
}

# Usar nombres descriptivos
good_topics = [
    "prod-pedidos-creados",
    "prod-usuarios-registrados",
    "prod-pagos-completados"
]
```

### 2. Políticas de Filtrado Eficientes

```python
# Filtro eficiente que reduce costos
efficient_filter = {
    "tipo": ["importante"],  # Solo mensajes importantes
    "destino": ["movil"],    # Solo para móviles
    "usuario_premium": ["true"]  # Solo usuarios premium
}

# Evitar filtros muy amplios
inefficient_filter = {
    "tipo": [{"anything-but": "spam"}]  # Procesa casi todo
}
```

### 3. Manejo de Mensajes Grandes

```python
# Para mensajes grandes, usar S3 + SNS
import boto3

def publish_large_message(topic_arn, large_data, bucket_name):
    # Subir a S3
    s3 = boto3.client('s3')
    key = f"sns-messages/{uuid.uuid4()}.json"
    s3.put_object(
        Bucket=bucket_name,
        Key=key,
        Body=json.dumps(large_data)
    )
    
    # Publicar referencia en SNS
    message = {
        "type": "large_message",
        "s3_bucket": bucket_name,
        "s3_key": key,
        "size_bytes": len(json.dumps(large_data))
    }
    
    return publish_message(topic_arn, message)
```

### 4. Reintentos y Circuit Breaker

```python
from functools import wraps
import time

def retry_with_backoff(max_retries=3, backoff_base=2):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'Throttling':
                        if attempt < max_retries - 1:
                            sleep_time = backoff_base ** attempt
                            time.sleep(sleep_time)
                            continue
                    raise
            raise Exception(f"Falló después de {max_retries} intentos")
        return wrapper
    return decorator

@retry_with_backoff(max_retries=3)
def publish_with_retry(topic_arn, message):
    return publish_message(topic_arn, message)
```

### 5. Monitoreo y Métricas

```python
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def publish_with_monitoring(topic_arn, message, metrics_client=None):
    start_time = datetime.now()
    
    try:
        response = publish_message(topic_arn, message)
        
        # Log exitoso
        logger.info(f"Mensaje publicado: {response['MessageId']}")
        
        # Enviar métrica de éxito
        if metrics_client:
            metrics_client.put_metric(
                namespace="MyApp/SNS",
                metric_name="MessagesPublished",
                value=1,
                dimensions=[
                    {"Name": "TopicName", "Value": topic_arn.split(":")[-1]}
                ]
            )
        
        return response
        
    except Exception as e:
        # Log error
        logger.error(f"Error publicando mensaje: {e}")
        
        # Enviar métrica de error
        if metrics_client:
            metrics_client.put_metric(
                namespace="MyApp/SNS",
                metric_name="PublishErrors",
                value=1
            )
        
        raise
    
    finally:
        # Registrar latencia
        duration = (datetime.now() - start_time).total_seconds()
        if metrics_client:
            metrics_client.put_metric(
                namespace="MyApp/SNS",
                metric_name="PublishLatency",
                value=duration,
                unit="Seconds"
            )
```

## Testing

### Mock para Pruebas Unitarias

```python
import pytest
from unittest.mock import patch, MagicMock
from custom_aws.sns import publish_message, subscribe

@patch('custom_aws.sns._get_sns_client')
def test_publish_message(mock_get_client):
    # Configurar mock
    mock_client = MagicMock()
    mock_get_client.return_value = mock_client
    mock_client.publish.return_value = {
        'MessageId': 'test-123',
        'ResponseMetadata': {'HTTPStatusCode': 200}
    }
    
    # Ejecutar
    result = publish_message(
        topic_arn="arn:aws:sns:eu-west-1:123456789:test",
        message="Test message"
    )
    
    # Verificar
    assert result['MessageId'] == 'test-123'
    mock_client.publish.assert_called_once()
```

### Usando Moto para Tests de Integración

```python
import boto3
from moto import mock_aws

@mock_aws
def test_sns_integration():
    # Crear cliente mock
    sns = boto3.client('sns', region_name='eu-west-1')
    
    # Crear tópico
    response = sns.create_topic(Name='test-topic')
    topic_arn = response['TopicArn']
    
    # Probar publicación
    from custom_aws.sns import publish_message
    result = publish_message(
        topic_arn=topic_arn,
        message="Test message",
        region_name='eu-west-1'
    )
    
    assert 'MessageId' in result
```

## Troubleshooting

### Error: "Invalid parameter: PhoneNumber"
- Verifica que el número incluya el código de país (ej: +34 para España)
- Asegúrate de que el número esté en formato E.164
- Confirma que tu cuenta tenga permisos para enviar SMS en esa región

### Error: "Topic does not exist"
- Verifica el ARN completo del tópico
- Confirma que el tópico existe en la región especificada
- Revisa que tengas permisos para acceder al tópico

### Mensajes no llegan a suscriptores
- Verifica las políticas de filtrado en las suscripciones
- Revisa los logs de CloudWatch para errores de entrega
- Confirma que los endpoints estén activos y accesibles
- Para email, revisa la carpeta de spam

### Throttling / Rate Limit
- Implementa reintentos con backoff exponencial
- Considera usar publicación en lote
- Distribuye la carga entre múltiples tópicos si es necesario
- Solicita aumento de límites si es necesario

### Suscripciones pendientes de confirmación
- Para email: el usuario debe confirmar desde el correo recibido
- Para HTTP/HTTPS: el endpoint debe responder correctamente al mensaje de confirmación
- Las suscripciones no confirmadas expiran después de 3 días