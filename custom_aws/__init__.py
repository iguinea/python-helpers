"""
AWS module - Utilidades para servicios AWS

Proporciona funciones helper para trabajar con servicios AWS como Secrets Manager y SQS.
"""

from .secrets import (
    get_secret_fields,
    parse_secret_json,
    check_secrets_manager_connection,
)

from .sqs import (
    send_message,
    send_message_batch,
    receive_messages,
    delete_message,
    delete_message_batch,
    get_queue_attributes,
    purge_queue,
    check_sqs_connection,
)

from .sns import (
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

__all__ = [
    # Secrets Manager
    "get_secret_fields",
    "parse_secret_json",
    "check_secrets_manager_connection",
    # SQS
    "send_message",
    "send_message_batch",
    "receive_messages",
    "delete_message",
    "delete_message_batch",
    "get_queue_attributes",
    "purge_queue",
    "check_sqs_connection",
    # SNS
    "publish_message",
    "publish_batch",
    "subscribe",
    "unsubscribe",
    "list_subscriptions_by_topic",
    "get_topic_attributes",
    "set_subscription_attributes",
    "confirm_subscription",
    "check_sns_connection",
]
