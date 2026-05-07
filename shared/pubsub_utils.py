"""
Pub/Sub Helpers — Publish and Subscribe utilities.
Production-ready: handles at-least-once delivery, idempotency, retries.

Usage:
    from shared.pubsub_utils import publish_message, create_push_subscription

    # Publish
    message_id = publish_message("scan.requests", json_payload)

    # Subscribe (for agent deployment — called once during setup)
    create_push_subscription(
        topic_name="scan.requests",
        subscription_name="scan.requests.agent-security",
        push_endpoint="https://agent-security-xxxxx-uc.a.run.app/",
        service_account="agent-security@PROJECT.iam.gserviceaccount.com"
    )
"""

import json
import os
from typing import Any, Dict, Optional

# google-cloud-pubsub is optional — only needed in GCP environment
try:
    from google.cloud import pubsub_v1
    PUBSUB_AVAILABLE = True
except ImportError:
    PUBSUB_AVAILABLE = False
    pubsub_v1 = None  # type: ignore


PROJECT = os.getenv("PROJECT_ID", os.getenv("GCP_PROJECT", ""))
IS_CLOUD = bool(PROJECT)


def _get_publisher():
    """Lazy-init Pub/Sub publisher client."""
    if not PUBSUB_AVAILABLE:
        raise RuntimeError(
            "google-cloud-pubsub not installed. "
            "Run: pip install google-cloud-pubsub"
        )
    return pubsub_v1.PublisherClient()


def topic_path(topic_name: str) -> str:
    """Build fully-qualified topic path: projects/{PROJECT}/topics/{name}."""
    if not PROJECT:
        raise RuntimeError("PROJECT_ID env var not set")
    return pubsub_v1.PublisherClient.topic_path(PROJECT, topic_name)


def subscription_path(subscription_name: str) -> str:
    """Build fully-qualified subscription path."""
    if not PROJECT:
        raise RuntimeError("PROJECT_ID env var not set")
    return pubsub_v1.SubscriberClient.subscription_path(PROJECT, subscription_name)


# ──────────────────────────────────────────────
#  Publish
# ──────────────────────────────────────────────

def publish_message(
    topic_name: str,
    data: str,
    ordering_key: Optional[str] = None,
    **attributes: str,
) -> Optional[str]:
    """
    Publish a message to a Pub/Sub topic.

    Args:
        topic_name: e.g. "scan.requests"
        data: JSON string payload
        ordering_key: Ensures in-order delivery for same key
        **attributes: Metadata key-value pairs attached to message

    Returns:
        message_id on success, None if Pub/Sub unavailable (local dev)
    """
    if not IS_CLOUD or not PUBSUB_AVAILABLE:
        print(f"[pubsub] LOCAL: Would publish to {topic_name}: {data[:200]}...")
        return None

    publisher = _get_publisher()
    future = publisher.publish(
        topic_path(topic_name),
        data=data.encode("utf-8"),
        ordering_key=ordering_key or "",
        **attributes,
    )
    message_id = future.result(timeout=30)
    print(f"[pubsub] Published to {topic_name} — msg_id: {message_id}")
    return message_id


def publish_scan_request(request_data: "ScanRequest") -> Optional[str]:
    """Publish a ScanRequest to the scan.requests topic."""

    payload = request_data.model_dump_json() if hasattr(request_data, 'model_dump_json') else json.dumps(request_data)
    return publish_message(
        "scan.requests",
        payload,
        ordering_key=request_data.request_id,
    )


def publish_scan_result(result_data: "ScanResult") -> Optional[str]:
    """Publish a ScanResult to the scan.results topic."""

    payload = result_data.model_dump_json() if hasattr(result_data, 'model_dump_json') else json.dumps(result_data)
    return publish_message(
        "scan.results",
        payload,
        ordering_key=result_data.request_id,
    )


# ──────────────────────────────────────────────
#  Subscribe (setup helpers — used at deploy time)
# ──────────────────────────────────────────────

def create_push_subscription(
    topic_name: str,
    subscription_name: str,
    push_endpoint: str,
    service_account: Optional[str] = None,
    ack_deadline_seconds: int = 600,
) -> Dict[str, Any]:
    """
    Create a Pub/Sub Push subscription with OIDC auth.

    Args:
        topic_name: e.g. "scan.requests"
        subscription_name: e.g. "scan.requests.agent-security"
        push_endpoint: Cloud Run URL of the agent, e.g. "https://agent-xxxxx-uc.a.run.app/"
        service_account: IAM service account for OIDC token generation
        ack_deadline_seconds: Max time for agent to ack (600 = 10 min for long scans)

    Returns:
        Subscription info dict
    """
    if not IS_CLOUD or not PUBSUB_AVAILABLE:
        print(f"[pubsub] LOCAL: Would create push subscription {subscription_name} → {push_endpoint}")
        return {"status": "local_dev_skip"}

    subscriber = pubsub_v1.SubscriberClient()
    push_config = pubsub_v1.types.PushConfig(
        push_endpoint=push_endpoint,
    )

    # Enable OIDC auth if service account provided
    if service_account:
        push_config.oidc_token = pubsub_v1.types.PushConfig.OidcToken(
            service_account_email=service_account,
            audience=push_endpoint,
        )

    subscription = subscriber.create_subscription(
        request={
            "name": subscription_path(subscription_name),
            "topic": topic_path(topic_name),
            "push_config": push_config,
            "ack_deadline_seconds": ack_deadline_seconds,
            "retry_policy": pubsub_v1.types.RetryPolicy(
                minimum_backoff=10,    # seconds
                maximum_backoff=600,   # 10 minutes
            ),
            "dead_letter_policy": pubsub_v1.types.DeadLetterPolicy(
                dead_letter_topic=topic_path(f"{topic_name}.dlq"),
                max_delivery_attempts=5,
            ),
        }
    )
    print(f"[pubsub] Created push subscription: {subscription_name}")
    return {"name": subscription.name, "push_endpoint": push_endpoint}


# ──────────────────────────────────────────────
#  Local Dev Shim — for testing without GCP
# ──────────────────────────────────────────────

def mock_pubsub_callback(topic_name: str, handler):
    """
    Local development: simulate receiving a Pub/Sub push message.
    Only used when PROJECT_ID is NOT set.

    Usage:
        def my_handler(message: dict):
            print("Got:", message)

        mock_pubsub_callback("scan.requests", my_handler)
    """
    if IS_CLOUD:
        raise RuntimeError("mock_pubsub_callback is for local dev only")

    import threading
    from flask import Flask, request

    app = Flask(__name__)

    @app.route("/", methods=["POST"])
    def handle_push():
        envelope = request.get_json(force=True, silent=True) or {}
        message_data = envelope.get("message", {}).get("data", "")
        # Base64 decode if needed
        import base64
        try:
            decoded = base64.b64decode(message_data).decode("utf-8")
        except Exception:
            decoded = message_data
        handler(json.loads(decoded))
        return ("", 204)

    thread = threading.Thread(target=lambda: app.run(port=8079, debug=False), daemon=True)
    thread.start()
    print(f"[pubsub mock] Listening on http://localhost:8079 for {topic_name}")
    return app