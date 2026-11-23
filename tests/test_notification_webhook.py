import pytest
from fastapi.testclient import TestClient

from app import main
from app.notifications import clear_notifications, get_notifications


client = TestClient(main.app)


@pytest.fixture(autouse=True)
def reset_notifications():
    clear_notifications()
    yield
    clear_notifications()


@pytest.fixture
def mock_rca(monkeypatch):
    def fake_analyze_alert(alert):
        return {
            "alert_name": alert.get("labels", {}).get("alertname", "Unknown"),
            "severity": alert.get("labels", {}).get("severity", "warning"),
            "status": alert.get("status", "firing"),
            "category": "Application",
            "namespace": alert.get("labels", {}).get("namespace", "unknown"),
            "pod": alert.get("labels", {}).get("pod", "unknown"),
            "node": "test-node",
            "deployment": "test-deployment",
            "summary": alert.get("annotations", {}).get("summary", ""),
            "probable_cause": "Simulated application failure.",
            "investigation": {"test": "local investigation"},
            "remediation": {
                "priority": "High",
                "reason": "Test recommendation",
                "evidence": ["Simulated evidence"],
                "recommendations": ["Inspect application logs"],
                "automatic_action": False,
            },
            "starts_at": alert.get("startsAt"),
            "analyzed_at": "2026-11-23T10:05:00Z",
        }

    monkeypatch.setattr(main, "analyze_alert", fake_analyze_alert)


def test_firing_webhook_creates_local_notification(mock_rca):
    payload = {
        "receiver": "local-test",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "PodCrashLooping",
                    "severity": "critical",
                    "namespace": "test-namespace",
                    "pod": "test-pod",
                },
                "annotations": {
                    "summary": "Container repeatedly restarting",
                },
            }
        ],
    }

    response = client.post("/webhook/alerts", json=payload)

    assert response.status_code == 200

    body = response.json()
    assert body["alerts_received"] == 1
    assert body["analysis"][0]["analysis"]["category"] == "Application"
    assert body["analysis"][0]["notification"]["status"] == "sent"

    notifications = get_notifications()
    assert len(notifications) == 1
    assert notifications[0]["alert_name"] == "PodCrashLooping"
    assert notifications[0]["severity"] == "critical"
    assert notifications[0]["pod"] == "test-pod"
    assert notifications[0]["remediation"]["automatic_action"] is False


def test_resolved_webhook_does_not_create_notification():
    payload = {
        "receiver": "local-test",
        "status": "resolved",
        "alerts": [
            {
                "status": "resolved",
                "labels": {
                    "alertname": "PodCrashLooping",
                },
            }
        ],
    }

    response = client.post("/webhook/alerts", json=payload)

    assert response.status_code == 200
    assert response.json()["analysis"][0]["status"] == "resolved"
    assert get_notifications() == []


def test_multiple_firing_alerts_create_multiple_notifications(mock_rca):
    payload = {
        "receiver": "local-test",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "PodCrashLooping"},
            },
            {
                "status": "firing",
                "labels": {"alertname": "NodeNotReady"},
            },
        ],
    }

    response = client.post("/webhook/alerts", json=payload)

    assert response.status_code == 200
    assert response.json()["alerts_received"] == 2
    assert len(get_notifications()) == 2

    assert get_notifications()[0]["notification_id"] == 1
    assert get_notifications()[1]["notification_id"] == 2


def test_notification_failure_does_not_break_rca(monkeypatch, mock_rca):
    def fail_notification(analysis):
        raise RuntimeError("Simulated notification failure")

    monkeypatch.setattr(main, "send_notification", fail_notification)

    payload = {
        "receiver": "local-test",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "PodCrashLooping"},
            }
        ],
    }

    response = client.post("/webhook/alerts", json=payload)

    assert response.status_code == 200

    result = response.json()["analysis"][0]
    assert result["analysis"]["probable_cause"]
    assert result["notification"]["status"] == "failed"


def test_resolved_alert_in_mixed_payload_is_not_notified(mock_rca):
    payload = {
        "receiver": "local-test",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "PodCrashLooping"},
            },
            {
                "status": "resolved",
                "labels": {"alertname": "NodeNotReady"},
            },
        ],
    }

    response = client.post("/webhook/alerts", json=payload)

    assert response.status_code == 200
    assert response.json()["alerts_received"] == 2
    assert len(get_notifications()) == 1
    assert get_notifications()[0]["alert_name"] == "PodCrashLooping"
