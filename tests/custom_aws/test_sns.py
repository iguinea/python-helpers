"""
Tests para el módulo custom_aws.sns
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError, NoCredentialsError

from custom_aws.sns import (
    _get_sns_client,
    publish_message,
    publish_batch,
    subscribe,
    unsubscribe,
    list_subscriptions_by_topic,
    get_topic_attributes,
    set_subscription_attributes,
    confirm_subscription,
    check_sns_connection,
)


class TestGetSnsClient:
    """Tests para la función _get_sns_client."""

    @patch.dict("os.environ", {}, clear=True)
    @patch("custom_aws.sns.boto3.Session")
    def test_get_client_default_region(self, mock_session):
        """Debe usar la región por defecto si no se especifica."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client

        result = _get_sns_client()

        mock_session.return_value.client.assert_called_once_with(
            service_name="sns", region_name="eu-west-1"
        )
        assert result == mock_client

    @patch("custom_aws.sns.boto3.Session")
    def test_get_client_custom_region(self, mock_session):
        """Debe usar la región especificada."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client

        result = _get_sns_client("us-east-1")

        mock_session.return_value.client.assert_called_once_with(
            service_name="sns", region_name="us-east-1"
        )
        assert result == mock_client

    @patch.dict("os.environ", {"AWS_DEFAULT_REGION": "ap-southeast-1"})
    @patch("custom_aws.sns.boto3.Session")
    def test_get_client_env_region(self, mock_session):
        """Debe usar la región del entorno si está configurada."""
        mock_client = Mock()
        mock_session.return_value.client.return_value = mock_client

        result = _get_sns_client()

        mock_session.return_value.client.assert_called_once_with(
            service_name="sns", region_name="ap-southeast-1"
        )
        assert result == mock_client

    @patch("custom_aws.sns.boto3.Session")
    def test_get_client_no_credentials(self, mock_session):
        """Debe lanzar NoCredentialsError si no hay credenciales."""
        mock_session.side_effect = NoCredentialsError()

        with pytest.raises(NoCredentialsError):
            _get_sns_client()


class TestPublishMessage:
    """Tests para la función publish_message."""

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_to_topic_simple(self, mock_get_client):
        """Debe publicar un mensaje simple a un tópico."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.publish.return_value = {
            "MessageId": "12345",
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }

        result = publish_message(
            topic_arn="arn:aws:sns:eu-west-1:123456789:mi-topico",
            message="Mensaje de prueba"
        )

        mock_client.publish.assert_called_once_with(
            TopicArn="arn:aws:sns:eu-west-1:123456789:mi-topico",
            Message="Mensaje de prueba"
        )
        assert result["MessageId"] == "12345"

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_to_phone_number(self, mock_get_client):
        """Debe publicar un SMS directo a un número de teléfono."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.publish.return_value = {"MessageId": "67890"}

        result = publish_message(
            phone_number="+34600123456",
            message="Código: 1234"
        )

        mock_client.publish.assert_called_once_with(
            PhoneNumber="+34600123456",
            Message="Código: 1234"
        )
        assert result["MessageId"] == "67890"

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_with_subject_and_attributes(self, mock_get_client):
        """Debe publicar con asunto y atributos."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.publish.return_value = {"MessageId": "abc123"}

        attributes = {
            "tipo": {"DataType": "String", "StringValue": "alerta"},
            "prioridad": {"DataType": "Number", "StringValue": "5"}
        }

        result = publish_message(
            topic_arn="arn:aws:sns:eu-west-1:123456789:alertas",
            message="Alerta del sistema",
            subject="Sistema crítico",
            message_attributes=attributes
        )

        mock_client.publish.assert_called_once_with(
            TopicArn="arn:aws:sns:eu-west-1:123456789:alertas",
            Message="Alerta del sistema",
            Subject="Sistema crítico",
            MessageAttributes=attributes
        )

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_dict_message(self, mock_get_client):
        """Debe convertir dict a JSON automáticamente."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.publish.return_value = {"MessageId": "123"}

        message_dict = {"tipo": "pedido", "id": 123, "total": 99.50}
        
        publish_message(
            topic_arn="arn:aws:sns:eu-west-1:123456789:pedidos",
            message=message_dict
        )

        # Verificar que se convirtió a JSON
        call_args = mock_client.publish.call_args[1]
        assert call_args["Message"] == json.dumps(message_dict, ensure_ascii=False)

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_json_structure(self, mock_get_client):
        """Debe publicar con estructura JSON para diferentes protocolos."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.publish.return_value = {"MessageId": "xyz789"}

        message_json = {
            "default": "Mensaje por defecto",
            "email": "Contenido detallado para email con HTML",
            "sms": "SMS corto"
        }

        publish_message(
            topic_arn="arn:aws:sns:eu-west-1:123456789:multi",
            message=json.dumps(message_json),
            message_structure="json"
        )

        mock_client.publish.assert_called_once()
        call_args = mock_client.publish.call_args[1]
        assert call_args["MessageStructure"] == "json"

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_fifo_topic(self, mock_get_client):
        """Debe publicar a un tópico FIFO con parámetros adicionales."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.publish.return_value = {
            "MessageId": "fifo123",
            "SequenceNumber": "12345678"
        }

        result = publish_message(
            topic_arn="arn:aws:sns:eu-west-1:123456789:mi-topico.fifo",
            message="Mensaje FIFO",
            message_group_id="grupo1",
            message_deduplication_id="dedup123"
        )

        mock_client.publish.assert_called_once_with(
            TopicArn="arn:aws:sns:eu-west-1:123456789:mi-topico.fifo",
            Message="Mensaje FIFO",
            MessageGroupId="grupo1",
            MessageDeduplicationId="dedup123"
        )
        assert result["SequenceNumber"] == "12345678"

    def test_publish_no_destination(self):
        """Debe fallar si no se proporciona topic_arn ni phone_number."""
        with pytest.raises(ValueError, match="Debe proporcionar topic_arn o phone_number"):
            publish_message(message="Mensaje sin destino")

    def test_publish_both_destinations(self):
        """Debe fallar si se proporcionan ambos destinos."""
        with pytest.raises(ValueError, match="Proporcione solo uno"):
            publish_message(
                topic_arn="arn:aws:sns:eu-west-1:123456789:topico",
                phone_number="+34600123456",
                message="Mensaje"
            )

    def test_publish_no_message(self):
        """Debe fallar si no se proporciona mensaje."""
        with pytest.raises(ValueError, match="El mensaje no puede estar vacío"):
            publish_message(topic_arn="arn:aws:sns:eu-west-1:123456789:topico")

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_topic_not_found(self, mock_get_client):
        """Debe manejar error cuando el tópico no existe."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        error_response = {"Error": {"Code": "NotFound", "Message": "Topic not found"}}
        mock_client.publish.side_effect = ClientError(error_response, "Publish")

        with pytest.raises(ValueError, match="El tópico no existe"):
            publish_message(
                topic_arn="arn:aws:sns:eu-west-1:123456789:no-existe",
                message="Test"
            )

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_access_denied(self, mock_get_client):
        """Debe manejar error de acceso denegado."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        error_response = {"Error": {"Code": "AuthorizationError", "Message": "Access denied"}}
        mock_client.publish.side_effect = ClientError(error_response, "Publish")

        with pytest.raises(PermissionError, match="Acceso denegado"):
            publish_message(
                topic_arn="arn:aws:sns:eu-west-1:123456789:restringido",
                message="Test"
            )


class TestPublishBatch:
    """Tests para la función publish_batch."""

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_batch_success(self, mock_get_client):
        """Debe publicar múltiples mensajes en lote."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.publish_batch.return_value = {
            "Successful": [
                {"Id": "1", "MessageId": "msg1"},
                {"Id": "2", "MessageId": "msg2"}
            ],
            "Failed": []
        }

        entries = [
            {"Id": "1", "Message": "Primer mensaje"},
            {"Id": "2", "Message": "Segundo mensaje", "Subject": "Alerta"}
        ]

        result = publish_batch(
            "arn:aws:sns:eu-west-1:123456789:batch-topic",
            entries
        )

        mock_client.publish_batch.assert_called_once_with(
            TopicArn="arn:aws:sns:eu-west-1:123456789:batch-topic",
            PublishBatchRequestEntries=entries
        )
        assert len(result["Successful"]) == 2
        assert len(result["Failed"]) == 0

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_batch_dict_conversion(self, mock_get_client):
        """Debe convertir mensajes dict a JSON."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.publish_batch.return_value = {
            "Successful": [{"Id": "1", "MessageId": "msg1"}],
            "Failed": []
        }

        entries = [
            {"Id": "1", "Message": {"tipo": "pedido", "id": 123}}
        ]

        publish_batch(
            "arn:aws:sns:eu-west-1:123456789:pedidos",
            entries
        )

        # Verificar que se convirtió a JSON
        call_args = mock_client.publish_batch.call_args[1]
        assert call_args["PublishBatchRequestEntries"][0]["Message"] == '{"tipo": "pedido", "id": 123}'

    def test_publish_batch_too_many_messages(self):
        """Debe fallar si hay más de 10 mensajes."""
        entries = [{"Id": str(i), "Message": f"Msg {i}"} for i in range(11)]

        with pytest.raises(ValueError, match="No se pueden publicar más de 10 mensajes"):
            publish_batch("arn:aws:sns:eu-west-1:123456789:topic", entries)

    def test_publish_batch_empty_list(self):
        """Debe fallar si la lista está vacía."""
        with pytest.raises(ValueError, match="La lista de mensajes no puede estar vacía"):
            publish_batch("arn:aws:sns:eu-west-1:123456789:topic", [])

    @patch("custom_aws.sns._get_sns_client")
    def test_publish_batch_partial_failure(self, mock_get_client):
        """Debe manejar fallos parciales en el lote."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.publish_batch.return_value = {
            "Successful": [{"Id": "1", "MessageId": "msg1"}],
            "Failed": [{
                "Id": "2",
                "Code": "InvalidParameter",
                "Message": "Invalid message"
            }]
        }

        entries = [
            {"Id": "1", "Message": "Mensaje válido"},
            {"Id": "2", "Message": ""}  # Mensaje inválido
        ]

        result = publish_batch(
            "arn:aws:sns:eu-west-1:123456789:topic",
            entries
        )

        assert len(result["Successful"]) == 1
        assert len(result["Failed"]) == 1
        assert result["Failed"][0]["Code"] == "InvalidParameter"


class TestSubscribe:
    """Tests para la función subscribe."""

    @patch("custom_aws.sns._get_sns_client")
    def test_subscribe_email(self, mock_get_client):
        """Debe suscribir un email a un tópico."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.subscribe.return_value = {
            "SubscriptionArn": "pending confirmation"
        }

        result = subscribe(
            topic_arn="arn:aws:sns:eu-west-1:123456789:alertas",
            protocol="email",
            endpoint="usuario@ejemplo.com"
        )

        mock_client.subscribe.assert_called_once_with(
            TopicArn="arn:aws:sns:eu-west-1:123456789:alertas",
            Protocol="email",
            Endpoint="usuario@ejemplo.com",
            ReturnSubscriptionArn=True
        )
        assert result["SubscriptionArn"] == "pending confirmation"

    @patch("custom_aws.sns._get_sns_client")
    def test_subscribe_sqs_with_filter(self, mock_get_client):
        """Debe suscribir una cola SQS con política de filtrado."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.subscribe.return_value = {
            "SubscriptionArn": "arn:aws:sns:eu-west-1:123456789:topico:sub123"
        }

        filter_policy = json.dumps({"tipo": ["error", "critico"]})
        
        result = subscribe(
            topic_arn="arn:aws:sns:eu-west-1:123456789:topico",
            protocol="sqs",
            endpoint="arn:aws:sqs:eu-west-1:123456789:mi-cola",
            attributes={"FilterPolicy": filter_policy}
        )

        mock_client.subscribe.assert_called_once()
        call_args = mock_client.subscribe.call_args[1]
        assert call_args["Attributes"]["FilterPolicy"] == filter_policy

    def test_subscribe_invalid_protocol(self):
        """Debe fallar con protocolo inválido."""
        with pytest.raises(ValueError, match="Protocolo inválido"):
            subscribe(
                topic_arn="arn:aws:sns:eu-west-1:123456789:topico",
                protocol="invalido",
                endpoint="algo"
            )

    @patch("custom_aws.sns._get_sns_client")
    def test_subscribe_lambda(self, mock_get_client):
        """Debe suscribir una función Lambda."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.subscribe.return_value = {
            "SubscriptionArn": "arn:aws:sns:eu-west-1:123456789:topico:lambda123"
        }

        subscribe(
            topic_arn="arn:aws:sns:eu-west-1:123456789:topico",
            protocol="lambda",
            endpoint="arn:aws:lambda:eu-west-1:123456789:function:mi-funcion"
        )

        call_args = mock_client.subscribe.call_args[1]
        assert call_args["Protocol"] == "lambda"


class TestUnsubscribe:
    """Tests para la función unsubscribe."""

    @patch("custom_aws.sns._get_sns_client")
    def test_unsubscribe_success(self, mock_get_client):
        """Debe cancelar una suscripción exitosamente."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client

        unsubscribe("arn:aws:sns:eu-west-1:123456789:topico:sub123")

        mock_client.unsubscribe.assert_called_once_with(
            SubscriptionArn="arn:aws:sns:eu-west-1:123456789:topico:sub123"
        )

    def test_unsubscribe_invalid_arn(self):
        """Debe fallar con ARN inválido."""
        with pytest.raises(ValueError, match="ARN de suscripción inválido"):
            unsubscribe("")

    def test_unsubscribe_pending_confirmation(self):
        """Debe fallar si está pendiente de confirmación."""
        with pytest.raises(ValueError, match="ARN de suscripción inválido"):
            unsubscribe("pending confirmation")

    @patch("custom_aws.sns._get_sns_client")
    def test_unsubscribe_not_found(self, mock_get_client):
        """Debe manejar error cuando la suscripción no existe."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        error_response = {"Error": {"Code": "NotFound", "Message": "Subscription not found"}}
        mock_client.unsubscribe.side_effect = ClientError(error_response, "Unsubscribe")

        with pytest.raises(ValueError, match="La suscripción no existe"):
            unsubscribe("arn:aws:sns:eu-west-1:123456789:topico:noexiste")


class TestListSubscriptionsByTopic:
    """Tests para la función list_subscriptions_by_topic."""

    @patch("custom_aws.sns._get_sns_client")
    def test_list_subscriptions_success(self, mock_get_client):
        """Debe listar suscripciones de un tópico."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_subscriptions_by_topic.return_value = {
            "Subscriptions": [
                {
                    "SubscriptionArn": "arn:aws:sns:eu-west-1:123456789:topico:sub1",
                    "Protocol": "email",
                    "Endpoint": "user1@example.com"
                },
                {
                    "SubscriptionArn": "arn:aws:sns:eu-west-1:123456789:topico:sub2",
                    "Protocol": "sqs",
                    "Endpoint": "arn:aws:sqs:eu-west-1:123456789:cola"
                }
            ]
        }

        result = list_subscriptions_by_topic("arn:aws:sns:eu-west-1:123456789:topico")

        assert len(result["Subscriptions"]) == 2
        assert result["Subscriptions"][0]["Protocol"] == "email"
        assert result["Subscriptions"][1]["Protocol"] == "sqs"

    @patch("custom_aws.sns._get_sns_client")
    def test_list_subscriptions_with_pagination(self, mock_get_client):
        """Debe manejar paginación con NextToken."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_subscriptions_by_topic.return_value = {
            "Subscriptions": [{"SubscriptionArn": "sub1"}],
            "NextToken": "token123"
        }

        result = list_subscriptions_by_topic(
            "arn:aws:sns:eu-west-1:123456789:topico",
            next_token="previousToken"
        )

        mock_client.list_subscriptions_by_topic.assert_called_once_with(
            TopicArn="arn:aws:sns:eu-west-1:123456789:topico",
            NextToken="previousToken"
        )
        assert result["NextToken"] == "token123"


class TestGetTopicAttributes:
    """Tests para la función get_topic_attributes."""

    @patch("custom_aws.sns._get_sns_client")
    def test_get_topic_attributes_success(self, mock_get_client):
        """Debe obtener atributos de un tópico."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_topic_attributes.return_value = {
            "Attributes": {
                "DisplayName": "Mi Tópico",
                "SubscriptionsConfirmed": "5",
                "SubscriptionsPending": "2",
                "Owner": "123456789",
                "FifoTopic": "false"
            }
        }

        result = get_topic_attributes("arn:aws:sns:eu-west-1:123456789:mi-topico")

        assert result["DisplayName"] == "Mi Tópico"
        assert result["SubscriptionsConfirmed"] == "5"
        assert result["FifoTopic"] == "false"

    @patch("custom_aws.sns._get_sns_client")
    def test_get_topic_attributes_fifo(self, mock_get_client):
        """Debe identificar tópicos FIFO."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.get_topic_attributes.return_value = {
            "Attributes": {
                "FifoTopic": "true",
                "ContentBasedDeduplication": "true"
            }
        }

        result = get_topic_attributes("arn:aws:sns:eu-west-1:123456789:mi-topico.fifo")

        assert result["FifoTopic"] == "true"
        assert result["ContentBasedDeduplication"] == "true"


class TestSetSubscriptionAttributes:
    """Tests para la función set_subscription_attributes."""

    @patch("custom_aws.sns._get_sns_client")
    def test_set_filter_policy(self, mock_get_client):
        """Debe configurar política de filtrado."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client

        filter_policy = json.dumps({
            "tipo": ["pedido", "factura"],
            "prioridad": [{"numeric": [">=", 5]}]
        })

        set_subscription_attributes(
            "arn:aws:sns:eu-west-1:123456789:topico:sub123",
            "FilterPolicy",
            filter_policy
        )

        mock_client.set_subscription_attributes.assert_called_once_with(
            SubscriptionArn="arn:aws:sns:eu-west-1:123456789:topico:sub123",
            AttributeName="FilterPolicy",
            AttributeValue=filter_policy
        )

    @patch("custom_aws.sns._get_sns_client")
    def test_set_raw_message_delivery(self, mock_get_client):
        """Debe configurar entrega de mensajes sin formato."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client

        set_subscription_attributes(
            "arn:aws:sns:eu-west-1:123456789:topico:sub123",
            "RawMessageDelivery",
            "true"
        )

        mock_client.set_subscription_attributes.assert_called_once()

    def test_set_invalid_attribute(self):
        """Debe fallar con atributo inválido."""
        with pytest.raises(ValueError, match="Atributo inválido"):
            set_subscription_attributes(
                "arn:aws:sns:eu-west-1:123456789:topico:sub123",
                "AtributoInvalido",
                "valor"
            )


class TestConfirmSubscription:
    """Tests para la función confirm_subscription."""

    @patch("custom_aws.sns._get_sns_client")
    def test_confirm_subscription_success(self, mock_get_client):
        """Debe confirmar una suscripción con el token."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.confirm_subscription.return_value = {
            "SubscriptionArn": "arn:aws:sns:eu-west-1:123456789:topico:sub123"
        }

        result = confirm_subscription(
            "arn:aws:sns:eu-west-1:123456789:topico",
            "abc123def456ghi789"
        )

        mock_client.confirm_subscription.assert_called_once_with(
            TopicArn="arn:aws:sns:eu-west-1:123456789:topico",
            Token="abc123def456ghi789",
            AuthenticateOnUnsubscribe="false"
        )
        assert result["SubscriptionArn"].endswith("sub123")

    @patch("custom_aws.sns._get_sns_client")
    def test_confirm_with_auth_on_unsubscribe(self, mock_get_client):
        """Debe configurar autenticación al desuscribir."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.confirm_subscription.return_value = {
            "SubscriptionArn": "arn:aws:sns:eu-west-1:123456789:topico:sub123"
        }

        confirm_subscription(
            "arn:aws:sns:eu-west-1:123456789:topico",
            "token123",
            authenticate_on_unsubscribe=True
        )

        call_args = mock_client.confirm_subscription.call_args[1]
        assert call_args["AuthenticateOnUnsubscribe"] == "true"

    @patch("custom_aws.sns._get_sns_client")
    def test_confirm_invalid_token(self, mock_get_client):
        """Debe manejar token inválido o expirado."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        error_response = {"Error": {"Code": "InvalidParameter", "Message": "Invalid token"}}
        mock_client.confirm_subscription.side_effect = ClientError(error_response, "ConfirmSubscription")

        with pytest.raises(ValueError, match="Token inválido o expirado"):
            confirm_subscription(
                "arn:aws:sns:eu-west-1:123456789:topico",
                "tokenInvalido"
            )


class TestCheckSnsConnection:
    """Tests para la función check_sns_connection."""

    @patch("custom_aws.sns._get_sns_client")
    def test_connection_success(self, mock_get_client):
        """Debe retornar True si la conexión es exitosa."""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        mock_client.list_topics.return_value = {"Topics": []}

        result = check_sns_connection()

        assert result is True
        mock_client.list_topics.assert_called_once_with(MaxResults=1)

    @patch("custom_aws.sns._get_sns_client")
    def test_connection_failure(self, mock_get_client):
        """Debe retornar False si falla la conexión."""
        mock_get_client.side_effect = Exception("Connection error")

        result = check_sns_connection()

        assert result is False

    @patch("custom_aws.sns._get_sns_client")
    @patch("builtins.print")
    def test_connection_failure_prints_error(self, mock_print, mock_get_client):
        """Debe imprimir el error cuando falla."""
        mock_get_client.side_effect = Exception("Connection error")

        check_sns_connection()

        mock_print.assert_called_once()
        assert "Prueba de conexión SNS falló" in mock_print.call_args[0][0]


# Tests de integración (marcados para skip por defecto)
@pytest.mark.integration
@pytest.mark.skip(reason="Requiere credenciales AWS reales")
class TestSnsIntegration:
    """Tests de integración con AWS SNS real."""

    def test_real_sns_connection(self):
        """Test real de conexión a SNS."""
        result = check_sns_connection()
        assert isinstance(result, bool)

    def test_publish_to_real_topic(self):
        """Test real de publicación a un tópico."""
        # Este test requeriría un ARN de tópico real
        topic_arn = "arn:aws:sns:eu-west-1:123456789:test-topic"
        
        try:
            result = publish_message(
                topic_arn=topic_arn,
                message="Test de integración",
                subject="Test"
            )
            assert "MessageId" in result
        except (ValueError, PermissionError, ClientError) as e:
            # Es esperado si no hay permisos o el tópico no existe
            pytest.skip(f"No se pudo probar: {e}")