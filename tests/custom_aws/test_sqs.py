"""
Tests para las utilidades SQS
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError, NoCredentialsError

from custom_aws.sqs import (
    send_message,
    send_message_batch,
    receive_messages,
    delete_message,
    delete_message_batch,
    get_queue_attributes,
    purge_queue,
    check_sqs_connection,
    _get_sqs_client,
)


class TestGetSQSClient:
    """Tests para _get_sqs_client"""
    
    @patch("custom_aws.sqs.boto3.Session")
    def test_get_sqs_client_success(self, mock_session):
        """Verificar creación exitosa del cliente"""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        client = _get_sqs_client("us-east-1")
        
        mock_session.return_value.client.assert_called_once_with(
            service_name="sqs",
            region_name="us-east-1"
        )
        assert client == mock_client
    
    @patch("custom_aws.sqs.boto3.Session")
    @patch.dict("os.environ", {"AWS_DEFAULT_REGION": "eu-central-1"})
    def test_get_sqs_client_default_region(self, mock_session):
        """Verificar uso de región por defecto desde entorno"""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client
        
        client = _get_sqs_client()
        
        mock_session.return_value.client.assert_called_once_with(
            service_name="sqs",
            region_name="eu-central-1"
        )
    
    @patch("custom_aws.sqs.boto3.Session")
    def test_get_sqs_client_no_credentials(self, mock_session):
        """Verificar manejo de error cuando no hay credenciales"""
        mock_session.return_value.client.side_effect = NoCredentialsError()
        
        with pytest.raises(NoCredentialsError):
            _get_sqs_client()


class TestSendMessage:
    """Tests para send_message"""
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_send_message_simple(self, mock_get_client):
        """Verificar envío de mensaje simple"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.send_message.return_value = {
            "MessageId": "12345",
            "MD5OfMessageBody": "abcdef"
        }
        
        result = send_message(
            "https://sqs.region.amazonaws.com/123/test-queue",
            "Test message"
        )
        
        mock_client.send_message.assert_called_once_with(
            QueueUrl="https://sqs.region.amazonaws.com/123/test-queue",
            MessageBody="Test message",
            DelaySeconds=0
        )
        assert result["MessageId"] == "12345"
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_send_message_with_dict_body(self, mock_get_client):
        """Verificar conversión automática de dict a JSON"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.send_message.return_value = {"MessageId": "12345"}
        
        message_dict = {"type": "order", "id": 123}
        send_message("queue_url", message_dict)
        
        # Verificar que se convirtió a JSON
        call_args = mock_client.send_message.call_args
        assert call_args[1]["MessageBody"] == json.dumps(message_dict, ensure_ascii=False)
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_send_message_with_attributes(self, mock_get_client):
        """Verificar envío con atributos del mensaje"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.send_message.return_value = {"MessageId": "12345"}
        
        attributes = {
            "Priority": {"DataType": "String", "StringValue": "High"}
        }
        
        send_message(
            "queue_url",
            "Test message",
            message_attributes=attributes,
            delay_seconds=5
        )
        
        mock_client.send_message.assert_called_once_with(
            QueueUrl="queue_url",
            MessageBody="Test message",
            DelaySeconds=5,
            MessageAttributes=attributes
        )
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_send_message_fifo_parameters(self, mock_get_client):
        """Verificar parámetros para colas FIFO"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.send_message.return_value = {"MessageId": "12345"}
        
        send_message(
            "queue_url.fifo",
            "Test message",
            message_group_id="group1",
            message_deduplication_id="dedup1"
        )
        
        call_args = mock_client.send_message.call_args[1]
        assert call_args["MessageGroupId"] == "group1"
        assert call_args["MessageDeduplicationId"] == "dedup1"
    
    def test_send_message_invalid_delay(self):
        """Verificar validación de delay_seconds"""
        with pytest.raises(ValueError, match="delay_seconds debe estar entre 0 y 900"):
            send_message("queue_url", "message", delay_seconds=1000)
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_send_message_queue_not_exists(self, mock_get_client):
        """Verificar manejo de error cuando la cola no existe"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.send_message.side_effect = ClientError(
            {"Error": {"Code": "QueueDoesNotExist"}},
            "send_message"
        )
        
        with pytest.raises(ValueError, match="La cola no existe"):
            send_message("queue_url", "message")
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_send_message_access_denied(self, mock_get_client):
        """Verificar manejo de error de permisos"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.send_message.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "send_message"
        )
        
        with pytest.raises(PermissionError, match="Acceso denegado"):
            send_message("queue_url", "message")


class TestSendMessageBatch:
    """Tests para send_message_batch"""
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_send_message_batch_success(self, mock_get_client):
        """Verificar envío exitoso de lote"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.send_message_batch.return_value = {
            "Successful": [
                {"Id": "1", "MessageId": "msg1"},
                {"Id": "2", "MessageId": "msg2"}
            ],
            "Failed": []
        }
        
        entries = [
            {"Id": "1", "MessageBody": "Message 1"},
            {"Id": "2", "MessageBody": "Message 2", "DelaySeconds": 5}
        ]
        
        result = send_message_batch("queue_url", entries)
        
        assert len(result["Successful"]) == 2
        assert len(result["Failed"]) == 0
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_send_message_batch_dict_conversion(self, mock_get_client):
        """Verificar conversión de dicts en MessageBody"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.send_message_batch.return_value = {"Successful": [], "Failed": []}
        
        entries = [
            {"Id": "1", "MessageBody": {"type": "order", "id": 123}}
        ]
        
        send_message_batch("queue_url", entries)
        
        call_args = mock_client.send_message_batch.call_args[1]
        assert call_args["Entries"][0]["MessageBody"] == '{"type": "order", "id": 123}'
    
    def test_send_message_batch_too_many(self):
        """Verificar límite de 10 mensajes"""
        entries = [{"Id": str(i), "MessageBody": f"Msg {i}"} for i in range(11)]
        
        with pytest.raises(ValueError, match="No se pueden enviar más de 10 mensajes"):
            send_message_batch("queue_url", entries)
    
    def test_send_message_batch_empty(self):
        """Verificar que no se puede enviar lista vacía"""
        with pytest.raises(ValueError, match="La lista de mensajes no puede estar vacía"):
            send_message_batch("queue_url", [])


class TestReceiveMessages:
    """Tests para receive_messages"""
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_receive_messages_simple(self, mock_get_client):
        """Verificar recepción simple de mensajes"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.receive_message.return_value = {
            "Messages": [
                {
                    "MessageId": "123",
                    "ReceiptHandle": "receipt123",
                    "Body": "Test message"
                }
            ]
        }
        
        messages = receive_messages("queue_url")
        
        assert len(messages) == 1
        assert messages[0]["Body"] == "Test message"
        mock_client.receive_message.assert_called_once_with(
            QueueUrl="queue_url",
            MaxNumberOfMessages=1,
            WaitTimeSeconds=0
        )
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_receive_messages_with_options(self, mock_get_client):
        """Verificar recepción con opciones"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.receive_message.return_value = {"Messages": []}
        
        receive_messages(
            "queue_url",
            max_messages=10,
            wait_time_seconds=20,
            visibility_timeout=300,
            attribute_names=["All"],
            message_attribute_names=["All"]
        )
        
        call_args = mock_client.receive_message.call_args[1]
        assert call_args["MaxNumberOfMessages"] == 10
        assert call_args["WaitTimeSeconds"] == 20
        assert call_args["VisibilityTimeout"] == 300
        assert call_args["AttributeNames"] == ["All"]
        assert call_args["MessageAttributeNames"] == ["All"]
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_receive_messages_no_messages(self, mock_get_client):
        """Verificar comportamiento cuando no hay mensajes"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.receive_message.return_value = {}
        
        messages = receive_messages("queue_url")
        
        assert messages == []
    
    def test_receive_messages_invalid_max(self):
        """Verificar validación de max_messages"""
        with pytest.raises(ValueError, match="max_messages debe estar entre 1 y 10"):
            receive_messages("queue_url", max_messages=15)
    
    def test_receive_messages_invalid_wait_time(self):
        """Verificar validación de wait_time_seconds"""
        with pytest.raises(ValueError, match="wait_time_seconds debe estar entre 0 y 20"):
            receive_messages("queue_url", wait_time_seconds=30)
    
    def test_receive_messages_invalid_visibility(self):
        """Verificar validación de visibility_timeout"""
        with pytest.raises(ValueError, match="visibility_timeout debe estar entre 0 y 43200"):
            receive_messages("queue_url", visibility_timeout=50000)


class TestDeleteMessage:
    """Tests para delete_message"""
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_delete_message_success(self, mock_get_client):
        """Verificar eliminación exitosa de mensaje"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        delete_message("queue_url", "receipt_handle_123")
        
        mock_client.delete_message.assert_called_once_with(
            QueueUrl="queue_url",
            ReceiptHandle="receipt_handle_123"
        )
    
    def test_delete_message_empty_handle(self):
        """Verificar validación de receipt_handle vacío"""
        with pytest.raises(ValueError, match="receipt_handle no puede estar vacío"):
            delete_message("queue_url", "")
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_delete_message_invalid_handle(self, mock_get_client):
        """Verificar manejo de receipt handle inválido"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.delete_message.side_effect = ClientError(
            {"Error": {"Code": "ReceiptHandleIsInvalid"}},
            "delete_message"
        )
        
        with pytest.raises(ValueError, match="El receipt handle es inválido"):
            delete_message("queue_url", "invalid_handle")


class TestDeleteMessageBatch:
    """Tests para delete_message_batch"""
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_delete_message_batch_success(self, mock_get_client):
        """Verificar eliminación exitosa de lote"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.delete_message_batch.return_value = {
            "Successful": [{"Id": "1"}, {"Id": "2"}],
            "Failed": []
        }
        
        entries = [
            {"Id": "1", "ReceiptHandle": "handle1"},
            {"Id": "2", "ReceiptHandle": "handle2"}
        ]
        
        result = delete_message_batch("queue_url", entries)
        
        assert len(result["Successful"]) == 2
        assert len(result["Failed"]) == 0
    
    def test_delete_message_batch_too_many(self):
        """Verificar límite de 10 mensajes"""
        entries = [{"Id": str(i), "ReceiptHandle": f"handle{i}"} for i in range(11)]
        
        with pytest.raises(ValueError, match="No se pueden eliminar más de 10 mensajes"):
            delete_message_batch("queue_url", entries)


class TestGetQueueAttributes:
    """Tests para get_queue_attributes"""
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_get_queue_attributes_all(self, mock_get_client):
        """Verificar obtención de todos los atributos"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_queue_attributes.return_value = {
            "Attributes": {
                "ApproximateNumberOfMessages": "5",
                "VisibilityTimeout": "30"
            }
        }
        
        attrs = get_queue_attributes("queue_url")
        
        assert attrs["ApproximateNumberOfMessages"] == "5"
        mock_client.get_queue_attributes.assert_called_once_with(
            QueueUrl="queue_url",
            AttributeNames=["All"]
        )
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_get_queue_attributes_specific(self, mock_get_client):
        """Verificar obtención de atributos específicos"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_queue_attributes.return_value = {
            "Attributes": {"ApproximateNumberOfMessages": "10"}
        }
        
        attrs = get_queue_attributes(
            "queue_url",
            ["ApproximateNumberOfMessages"]
        )
        
        assert attrs["ApproximateNumberOfMessages"] == "10"


class TestPurgeQueue:
    """Tests para purge_queue"""
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_purge_queue_success(self, mock_get_client):
        """Verificar purga exitosa de cola"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        purge_queue("queue_url")
        
        mock_client.purge_queue.assert_called_once_with(QueueUrl="queue_url")
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_purge_queue_in_progress(self, mock_get_client):
        """Verificar manejo de purga en progreso"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.purge_queue.side_effect = ClientError(
            {"Error": {"Code": "PurgeQueueInProgress"}},
            "purge_queue"
        )
        
        with pytest.raises(ValueError, match="Ya hay una purga en progreso"):
            purge_queue("queue_url")


class TestCheckSQSConnection:
    """Tests para check_sqs_connection"""
    
    @patch("custom_aws.sqs._get_sqs_client")
    def test_check_connection_success(self, mock_get_client):
        """Verificar conexión exitosa"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_queues.return_value = {"QueueUrls": []}
        
        result = check_sqs_connection()
        
        assert result is True
        mock_client.list_queues.assert_called_once_with(MaxResults=1)
    
    @patch("custom_aws.sqs._get_sqs_client")
    @patch("builtins.print")
    def test_check_connection_failure(self, mock_print, mock_get_client):
        """Verificar manejo de fallo en conexión"""
        mock_get_client.side_effect = Exception("Connection failed")
        
        result = check_sqs_connection()
        
        assert result is False
        mock_print.assert_called_once()


@pytest.mark.integration
class TestSQSIntegration:
    """Tests de integración con AWS SQS (requiere credenciales AWS)"""
    
    @pytest.mark.skip(reason="Requiere credenciales AWS y cola SQS real")
    def test_full_message_flow(self):
        """Test completo de envío, recepción y eliminación"""
        queue_url = "https://sqs.region.amazonaws.com/account/test-queue"
        
        # Enviar mensaje
        send_result = send_message(queue_url, {"test": "integration"})
        assert "MessageId" in send_result
        
        # Recibir mensaje
        messages = receive_messages(queue_url, wait_time_seconds=2)
        assert len(messages) > 0
        
        # Eliminar mensaje
        for msg in messages:
            delete_message(queue_url, msg["ReceiptHandle"])