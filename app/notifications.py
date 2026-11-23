"""Local notification service for the Kubernetes RCA agent.

Notifications are stored in memory only.
No email, Slack messages, network calls, or automatic remediation.
"""

import os
import time
from copy import deepcopy
from threading import Lock
from typing import Any


SEVERITY_LEVELS = {
    "info": 1,
    "warning": 2,
    "critical": 3,
}

DEFAULT_MINIMUM_SEVERITY = "warning"
DEFAULT_DEDUPE_SECONDS = 600

_state_lock = Lock()
_last_notification_at: dict[tuple[str, str, str], float] = {}


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


def _get_minimum_severity() -> str:
    """Read the configured minimum notification severity."""

    configured = os.getenv(
        "RCA_NOTIFICATION_MIN_SEVERITY",
        DEFAULT_MINIMUM_SEVERITY,
    ).strip().lower()

    if configured not in SEVERITY_LEVELS:
        return DEFAULT_MINIMUM_SEVERITY

    return configured


def _get_dedupe_seconds() -> int:
    """Read the duplicate suppression cooldown."""

    configured = os.getenv(
        "RCA_NOTIFICATION_DEDUPE_SECONDS",
        str(DEFAULT_DEDUPE_SECONDS),
    )

    try:
        seconds = int(configured)
    except (TypeError, ValueError):
        return DEFAULT_DEDUPE_SECONDS

    return max(0, seconds)


def _get_alert_fingerprint(
    notification: dict[str, Any],
) -> tuple[str, str, str]:
    """Build a stable identity for the same alert and affected pod."""

    return (
        str(notification.get("alert_name") or "unknown").strip().lower(),
        str(notification.get("namespace") or "unknown").strip().lower(),
        str(notification.get("pod") or "unknown").strip().lower(),
    )


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
    """Filter, deduplicate, and record a firing alert locally."""

    status = str(analysis.get("status", "unknown")).strip().lower()

    if status != "firing":
        return {
            "status": "skipped",
            "reason": "Only firing alerts generate notifications.",
        }

    notification = build_notification(analysis)

    severity = str(notification.get("severity") or "unknown").strip().lower()
    minimum_severity = _get_minimum_severity()

    severity_level = SEVERITY_LEVELS.get(severity)
    minimum_level = SEVERITY_LEVELS[minimum_severity]

    if severity_level is None or severity_level < minimum_level:
        return {
            "status": "skipped",
            "filter": "severity",
            "reason": (
                f"Alert severity '{severity}' does not meet "
                f"the minimum configured severity '{minimum_severity}'."
            ),
        }

    cooldown = _get_dedupe_seconds()
    fingerprint = _get_alert_fingerprint(notification)

    with _state_lock:
        now = time.monotonic()

        if cooldown > 0:
            # Remove expired fingerprints to prevent unbounded growth.
            expired = [
                key
                for key, last_sent in _last_notification_at.items()
                if now - last_sent >= cooldown
            ]

            for key in expired:
                del _last_notification_at[key]

            previous_sent = _last_notification_at.get(fingerprint)

            if previous_sent is not None:
                elapsed = now - previous_sent

                if elapsed < cooldown:
                    return {
                        "status": "suppressed",
                        "reason": (
                            "Duplicate alert suppressed during "
                            "the configured cooldown period."
                        ),
                        "retry_after_seconds": round(
                            cooldown - elapsed, 2
                        ),
                    }

            _last_notification_at[fingerprint] = now

        return local_sink.send(notification)


def get_notifications() -> list[dict[str, Any]]:
    """Return notifications received by the local sink."""

    return local_sink.get_all()


def clear_notifications() -> None:
    """Reset notifications and duplicate tracking for tests."""

    with _state_lock:
        local_sink.clear()
        _last_notification_at.clear()
