"""Local notification service for the Kubernetes RCA agent.

This implementation records notifications in memory.
It does not send email, Slack messages, or make network requests.
"""

from copy import deepcopy
from threading import Lock
from typing import Any


class LocalNotificationSink:
    """In-memory receiver used for local development and testing."""

    def __init__(self):
        self._notifications: list[dict[str, Any]] = []
        self._lock = Lock()

    def send(self, notification: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            saved = deepcopy(notification)
            saved["notification_id"] = len(self._notifications) + 1
            self._notifications.append(saved)

        return {
            "status": "sent",
            "notification_id": saved["notification_id"],
        }

    def get_all(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(self._notifications)

    def clear(self) -> None:
        with self._lock:
            self._notifications.clear()


local_sink = LocalNotificationSink()


def build_notification(analysis: dict[str, Any]) -> dict[str, Any]:
    """Convert an RCA result into a notification payload."""

    remediation = analysis.get("remediation") or {}
    investigation = analysis.get("investigation") or {}

    return {
        "alert_name": analysis.get("alert_name", "Unknown"),
        "severity": analysis.get("severity", "unknown"),
        "status": analysis.get("status", "unknown"),
        "category": analysis.get("category", "Unknown"),
        "namespace": analysis.get("namespace", "unknown"),
        "pod": analysis.get("pod", "unknown"),
        "node": analysis.get("node", "unknown"),
        "deployment": analysis.get("deployment", "unknown"),
        "summary": analysis.get("summary", ""),
        "probable_cause": analysis.get("probable_cause", ""),
        "investigation": investigation,
        "remediation": {
            "priority": remediation.get("priority", "Not set"),
            "reason": remediation.get("reason", ""),
            "evidence": remediation.get("evidence", []),
            "recommendations": remediation.get("recommendations", []),
            "automatic_action": False,
        },
        "starts_at": analysis.get("starts_at"),
        "analyzed_at": analysis.get("analyzed_at"),
    }


def send_notification(analysis: dict[str, Any]) -> dict[str, Any]:
    """Record a notification for a firing alert.

    This function never performs remediation or external network calls.
    """

    status = str(analysis.get("status", "unknown")).lower()

    if status != "firing":
        return {
            "status": "skipped",
            "reason": "Only firing alerts generate notifications.",
        }

    notification = build_notification(analysis)
    return local_sink.send(notification)


def get_notifications() -> list[dict[str, Any]]:
    """Return notifications received by the local sink."""

    return local_sink.get_all()


def clear_notifications() -> None:
    """Clear the local receiver. Intended for tests and local development."""

    local_sink.clear()
