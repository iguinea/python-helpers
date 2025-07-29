# AWS SQS - Utilidades para Amazon Simple Queue Service

Este módulo proporciona funciones helper para interactuar con Amazon SQS, permitiendo enviar, recibir y gestionar mensajes en colas SQS de forma sencilla.

## Instalación

```bash
pip install -e .
```

## Configuración

Las funciones utilizan las credenciales AWS estándar. Puedes configurarlas mediante:

1. Variables de entorno:
```bash
export AWS_ACCESS_KEY_ID="tu-access-key"
export AWS_SECRET_ACCESS_KEY="tu-secret-key"
export AWS_DEFAULT_REGION="eu-west-1"
```

2. Archivo de credenciales AWS (`~/.aws/credentials`)

3. Rol IAM (en EC2, Lambda, etc.)

## Funciones Disponibles

### send_message

Envía un mensaje individual a una cola SQS.

```python
from custom_aws.sqs import send_message

# Enviar mensaje simple
response = send_message(
    "https://sqs.eu-west-1.amazonaws.com/123456789/mi-cola",
    "Hola mundo"
)
print(f"Message ID: {response['MessageId']}")

# Enviar mensaje JSON
response = send_message(
    queue_url,
    {"tipo": "pedido", "id": 123, "total": 99.99}
)

# Enviar con atributos y retraso
response = send_message(
    queue_url,
    "Mensaje importante",
    message_attributes={
        "Prioridad": {"DataType": "String", "StringValue": "Alta"},
        "Timestamp": {"DataType": "Number", "StringValue": "1234567890"}
    },
    delay_seconds=60  # Retrasar 60 segundos
)

# Para colas FIFO
response = send_message(
    "https://sqs.region.amazonaws.com/123/mi-cola.fifo",
    "Mensaje FIFO",
    message_group_id="grupo1",
    message_deduplication_id="unique-id-123"
)
```

### send_message_batch

Envía múltiples mensajes en un solo lote (máximo 10).

```python
from custom_aws.sqs import send_message_batch

messages = [
    {
        "Id": "1",
        "MessageBody": "Primer mensaje"
    },
    {
        "Id": "2",
        "MessageBody": json.dumps({"tipo": "notificación"}),
        "DelaySeconds": 30
    },
    {
        "Id": "3",
        "MessageBody": "Mensaje con atributos",
        "MessageAttributes": {
            "Tipo": {"DataType": "String", "StringValue": "Urgente"}
        }
    }
]

response = send_message_batch(queue_url, messages)

print(f"Enviados exitosamente: {len(response['Successful'])}")
if response.get('Failed'):
    print(f"Fallos: {len(response['Failed'])}")
    for failure in response['Failed']:
        print(f"  ID {failure['Id']}: {failure['Message']}")
```

### receive_messages

Recibe mensajes de una cola SQS.

```python
from custom_aws.sqs import receive_messages

# Recibir un mensaje
messages = receive_messages(queue_url)
for msg in messages:
    print(f"Body: {msg['Body']}")
    print(f"Receipt Handle: {msg['ReceiptHandle']}")

# Recibir múltiples mensajes con long polling
messages = receive_messages(
    queue_url,
    max_messages=10,
    wait_time_seconds=20  # Esperar hasta 20 segundos por mensajes
)

# Recibir con atributos y visibility timeout personalizado
messages = receive_messages(
    queue_url,
    visibility_timeout=300,  # 5 minutos
    attribute_names=['All'],
    message_attribute_names=['All']
)

# Procesar mensajes JSON
for msg in messages:
    try:
        data = json.loads(msg['Body'])
        print(f"Tipo: {data.get('tipo')}")
    except json.JSONDecodeError:
        print(f"Mensaje no JSON: {msg['Body']}")
```

### delete_message

Elimina un mensaje procesado de la cola.

```python
from custom_aws.sqs import delete_message, receive_messages

# Flujo típico: recibir y procesar
messages = receive_messages(queue_url)
for msg in messages:
    try:
        # Procesar el mensaje
        process_message(msg['Body'])
        
        # Si todo salió bien, eliminar el mensaje
        delete_message(queue_url, msg['ReceiptHandle'])
        print(f"Mensaje {msg['MessageId']} procesado y eliminado")
    except Exception as e:
        print(f"Error procesando mensaje: {e}")
        # El mensaje volverá a ser visible después del visibility timeout
```

### delete_message_batch

Elimina múltiples mensajes en lote.

```python
from custom_aws.sqs import delete_message_batch

# Preparar lista de mensajes a eliminar
entries = []
for i, msg in enumerate(messages_to_delete):
    entries.append({
        "Id": str(i),
        "ReceiptHandle": msg['ReceiptHandle']
    })

# Eliminar en lote (máximo 10)
if entries:
    response = delete_message_batch(queue_url, entries[:10])
    
    if response.get('Failed'):
        for failure in response['Failed']:
            print(f"Fallo al eliminar: {failure['Message']}")
```

### get_queue_attributes

Obtiene información sobre la cola.

```python
from custom_aws.sqs import get_queue_attributes

# Obtener todos los atributos
attrs = get_queue_attributes(queue_url)
print(f"Mensajes en cola: {attrs['ApproximateNumberOfMessages']}")
print(f"Mensajes en proceso: {attrs['ApproximateNumberOfMessagesNotVisible']}")
print(f"Visibility timeout: {attrs['VisibilityTimeout']} segundos")

# Obtener atributos específicos
attrs = get_queue_attributes(
    queue_url,
    ['ApproximateNumberOfMessages', 'QueueArn']
)

# Verificar si es cola FIFO
if attrs.get('FifoQueue') == 'true':
    print("Es una cola FIFO")
```

### purge_queue

Elimina TODOS los mensajes de una cola (usar con precaución).

```python
from custom_aws.sqs import purge_queue

# ¡CUIDADO! Esto eliminará TODOS los mensajes
# Solo se puede hacer una vez cada 60 segundos
try:
    purge_queue(queue_url)
    print("Cola vaciada exitosamente")
except ValueError as e:
    if "purga en progreso" in str(e):
        print("Ya hay una purga en progreso, espera 60 segundos")
```

### check_sqs_connection

Verifica la conectividad con SQS.

```python
from custom_aws.sqs import check_sqs_connection

if check_sqs_connection():
    print("Conexión a SQS exitosa")
else:
    print("No se pudo conectar a SQS")
```

## Ejemplos Completos

### Productor de mensajes

```python
import json
from custom_aws.sqs import send_message, send_message_batch

class MessageProducer:
    def __init__(self, queue_url):
        self.queue_url = queue_url
    
    def send_order(self, order_data):
        """Envía una orden a la cola"""
        message = {
            "type": "order",
            "timestamp": int(time.time()),
            "data": order_data
        }
        
        response = send_message(
            self.queue_url,
            message,
            message_attributes={
                "OrderId": {
                    "DataType": "String",
                    "StringValue": order_data['order_id']
                }
            }
        )
        return response['MessageId']
    
    def send_batch_notifications(self, notifications):
        """Envía múltiples notificaciones en lote"""
        entries = []
        for i, notif in enumerate(notifications[:10]):  # Máximo 10
            entries.append({
                "Id": str(i),
                "MessageBody": json.dumps(notif),
                "MessageAttributes": {
                    "Type": {
                        "DataType": "String",
                        "StringValue": notif.get('type', 'info')
                    }
                }
            })
        
        return send_message_batch(self.queue_url, entries)
```

### Consumidor de mensajes

```python
import json
import time
from custom_aws.sqs import receive_messages, delete_message, get_queue_attributes

class MessageConsumer:
    def __init__(self, queue_url):
        self.queue_url = queue_url
        self.running = True
    
    def process_message(self, message):
        """Procesa un mensaje individual"""
        try:
            body = json.loads(message['Body'])
            message_type = body.get('type')
            
            if message_type == 'order':
                self.process_order(body['data'])
            elif message_type == 'notification':
                self.process_notification(body['data'])
            else:
                print(f"Tipo de mensaje desconocido: {message_type}")
            
            return True
        except Exception as e:
            print(f"Error procesando mensaje: {e}")
            return False
    
    def consume_messages(self):
        """Loop principal del consumidor"""
        while self.running:
            try:
                # Recibir mensajes con long polling
                messages = receive_messages(
                    self.queue_url,
                    max_messages=10,
                    wait_time_seconds=20,
                    visibility_timeout=60,  # 1 minuto para procesar
                    attribute_names=['All']
                )
                
                if not messages:
                    print("No hay mensajes nuevos")
                    continue
                
                print(f"Recibidos {len(messages)} mensajes")
                
                for msg in messages:
                    # Verificar número de intentos
                    receive_count = int(
                        msg.get('Attributes', {}).get('ApproximateReceiveCount', 0)
                    )
                    
                    if receive_count > 3:
                        print(f"Mensaje recibido {receive_count} veces, enviando a DLQ")
                        # Aquí podrías enviar a una Dead Letter Queue
                        delete_message(self.queue_url, msg['ReceiptHandle'])
                        continue
                    
                    # Procesar mensaje
                    if self.process_message(msg):
                        # Si se procesó correctamente, eliminar
                        delete_message(self.queue_url, msg['ReceiptHandle'])
                        print(f"Mensaje {msg['MessageId']} procesado")
                    else:
                        print(f"Mensaje {msg['MessageId']} será reintentado")
                        # No eliminar, volverá a ser visible
                
            except KeyboardInterrupt:
                print("Deteniendo consumidor...")
                self.running = False
            except Exception as e:
                print(f"Error en consumidor: {e}")
                time.sleep(5)  # Esperar antes de reintentar
    
    def get_queue_stats(self):
        """Obtiene estadísticas de la cola"""
        attrs = get_queue_attributes(self.queue_url)
        return {
            "messages_available": int(attrs.get('ApproximateNumberOfMessages', 0)),
            "messages_in_flight": int(attrs.get('ApproximateNumberOfMessagesNotVisible', 0)),
            "oldest_message_age": attrs.get('ApproximateAgeOfOldestMessage')
        }
```

### Monitor de cola

```python
import time
from custom_aws.sqs import get_queue_attributes

def monitor_queue(queue_url, interval=30):
    """Monitorea el estado de una cola SQS"""
    while True:
        try:
            attrs = get_queue_attributes(queue_url)
            
            messages = int(attrs.get('ApproximateNumberOfMessages', 0))
            in_flight = int(attrs.get('ApproximateNumberOfMessagesNotVisible', 0))
            
            print(f"\n--- Estado de la cola ---")
            print(f"Mensajes disponibles: {messages}")
            print(f"Mensajes en proceso: {in_flight}")
            print(f"Total: {messages + in_flight}")
            
            if 'ApproximateAgeOfOldestMessage' in attrs:
                age = int(attrs['ApproximateAgeOfOldestMessage'])
                print(f"Edad del mensaje más antiguo: {age} segundos")
            
            # Alertas
            if messages > 100:
                print("⚠️  ALERTA: Más de 100 mensajes en cola")
            
            if in_flight > 50:
                print("⚠️  ALERTA: Muchos mensajes en proceso")
            
            time.sleep(interval)
            
        except KeyboardInterrupt:
            print("\nMonitoreo detenido")
            break
        except Exception as e:
            print(f"Error monitoreando: {e}")
            time.sleep(interval)
```

## Manejo de Errores

Las funciones pueden lanzar las siguientes excepciones:

- `ValueError`: Parámetros inválidos o cola no existe
- `PermissionError`: Falta de permisos IAM
- `NoCredentialsError`: Credenciales AWS no configuradas
- `ClientError`: Otros errores de AWS

```python
from botocore.exceptions import ClientError, NoCredentialsError
from custom_aws.sqs import send_message

try:
    response = send_message(queue_url, "mensaje")
except ValueError as e:
    print(f"Error de validación: {e}")
except PermissionError as e:
    print(f"Error de permisos: {e}")
except NoCredentialsError:
    print("Configure las credenciales AWS")
except ClientError as e:
    print(f"Error de AWS: {e}")
```

## Permisos IAM Requeridos

Para usar estas funciones, necesitas los siguientes permisos IAM:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sqs:SendMessage",
                "sqs:SendMessageBatch",
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
                "sqs:DeleteMessageBatch",
                "sqs:GetQueueAttributes",
                "sqs:PurgeQueue",
                "sqs:ListQueues"
            ],
            "Resource": "arn:aws:sqs:region:account-id:queue-name"
        }
    ]
}
```

## Mejores Prácticas

1. **Long Polling**: Usa `wait_time_seconds` > 0 para reducir costos y latencia
2. **Batch Operations**: Usa `send_message_batch` y `delete_message_batch` cuando sea posible
3. **Visibility Timeout**: Ajusta según el tiempo de procesamiento esperado
4. **Dead Letter Queues**: Configura DLQ para mensajes que fallan repetidamente
5. **Manejo de Errores**: Siempre maneja excepciones al procesar mensajes
6. **Idempotencia**: Diseña tu procesamiento para ser idempotente
7. **Monitoreo**: Monitorea regularmente el tamaño de la cola y mensajes antiguos

## Limitaciones

- Tamaño máximo de mensaje: 256 KB
- Máximo mensajes por lote: 10
- Visibility timeout máximo: 12 horas
- Long polling máximo: 20 segundos
- Retención de mensajes: 1 minuto a 14 días (configurable en la cola)