import pytest

from app.notifications import (
    clear_notifications,
    get_notifications,
    send_notification,
)


@pytest.fixture(autouse=True)
def reset_local_notifications():
    clear_notifications()
    yield
    clear_notifications()


@pytest.fixture
def sample_rca():
    return {
        "alert_name": "PodCrashLooping",
        "severity": "critical",
        "status": "firing",
        "category": "Application",
        "namespace": "test-namespace",
        "pod": "test-pod",
        "node": "test-node",
        "deployment": "test-deployment",
        "summary": "Container repeatedly restarting",
        "probable_cause": "The application container is repeatedly crashing.",
        "investigation": {
            "pod_details": {
                "status": "success",
                "restart_count": 5,
            }
        },
        "remediation": {
            "status": "generated",
            "priority": "High",
            "automatic_action": False,
            "reason": "Repeated container failures detected.",
            "evidence": ["Container restart count is 5."],
            "recommendations": ["Inspect previous container logs."],
        },
        "starts_at": "2026-11-23T10:00:00Z",
        "analyzed_at": "2026-11-23T10:05:00Z",
    }


def test_firing_alert_generates_local_notification(sample_rca):
    result = send_notification(sample_rca)

    assert result["status"] == "sent"
    assert result["notification_id"] == 1

    notifications = get_notifications()
    assert len(notifications) == 1

    notification = notifications[0]
    assert notification["alert_name"] == "PodCrashLooping"
    assert notification["severity"] == "critical"
    assert notification["category"] == "Application"
    assert notification["namespace"] == "test-namespace"
    assert notification["pod"] == "test-pod"
    assert notification["probable_cause"]
    assert notification["investigation"]["pod_details"]["restart_count"] == 5


def test_notification_contains_remediation_recommendations(sample_rca):
    send_notification(sample_rca)

    notification = get_notifications()[0]

    assert notification["remediation"]["priority"] == "High"
    assert notification["remediation"]["recommendations"] == [
        "Inspect previous container logs."
    ]
    assert notification["remediation"]["automatic_action"] is False


def test_resolved_alert_does_not_generate_notification(sample_rca):
    sample_rca["status"] = "resolved"

    result = send_notification(sample_rca)

    assert result["status"] == "skipped"
    assert get_notifications() == []


def test_unknown_alert_status_does_not_generate_notification(sample_rca):
    sample_rca["status"] = "unknown"

    result = send_notification(sample_rca)

    assert result["status"] == "skipped"
    assert get_notifications() == []


def test_multiple_alerts_receive_unique_notification_ids(sample_rca):
    first = send_notification(sample_rca)

    second_rca = dict(sample_rca)
    second_rca["alert_name"] = "NodeNotReady"
    second_rca["category"] = "Infrastructure"

    second = send_notification(second_rca)

    assert first["notification_id"] == 1
    assert second["notification_id"] == 2
    assert len(get_notifications()) == 2


def test_notification_does_not_enable_automatic_remediation(sample_rca):
    sample_rca["remediation"]["automatic_action"] = True

    send_notification(sample_rca)

    notification = get_notifications()[0]
    assert notification["remediation"]["automatic_action"] is False
