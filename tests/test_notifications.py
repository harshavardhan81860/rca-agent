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


def test_info_severity_is_filtered(sample_rca, monkeypatch):
    import app.notifications as notifications

    monkeypatch.setenv("RCA_NOTIFICATION_MIN_SEVERITY", "warning")
    sample_rca["severity"] = "info"

    result = notifications.send_notification(sample_rca)

    assert result["status"] == "skipped"
    assert result["filter"] == "severity"
    assert get_notifications() == []


def test_unknown_severity_is_filtered(sample_rca, monkeypatch):
    import app.notifications as notifications

    monkeypatch.setenv("RCA_NOTIFICATION_MIN_SEVERITY", "warning")
    sample_rca["severity"] = "unknown"

    result = notifications.send_notification(sample_rca)

    assert result["status"] == "skipped"
    assert result["filter"] == "severity"
    assert get_notifications() == []


def test_warning_severity_is_accepted(sample_rca, monkeypatch):
    import app.notifications as notifications

    monkeypatch.setenv("RCA_NOTIFICATION_MIN_SEVERITY", "warning")
    monkeypatch.setenv("RCA_NOTIFICATION_DEDUPE_SECONDS", "600")
    sample_rca["severity"] = "warning"

    result = notifications.send_notification(sample_rca)

    assert result["status"] == "sent"
    assert len(get_notifications()) == 1


def test_duplicate_alert_is_suppressed(sample_rca, monkeypatch):
    import app.notifications as notifications

    monkeypatch.setenv("RCA_NOTIFICATION_DEDUPE_SECONDS", "600")

    first = notifications.send_notification(sample_rca)
    second = notifications.send_notification(sample_rca)

    assert first["status"] == "sent"
    assert second["status"] == "suppressed"
    assert second["retry_after_seconds"] > 0
    assert len(get_notifications()) == 1


def test_different_pods_are_not_treated_as_duplicates(
    sample_rca, monkeypatch
):
    import app.notifications as notifications

    monkeypatch.setenv("RCA_NOTIFICATION_DEDUPE_SECONDS", "600")

    first = notifications.send_notification(sample_rca)

    second_rca = dict(sample_rca)
    second_rca["pod"] = "another-pod"

    second = notifications.send_notification(second_rca)

    assert first["status"] == "sent"
    assert second["status"] == "sent"
    assert len(get_notifications()) == 2


def test_duplicate_can_be_sent_after_cooldown_expires(
    sample_rca, monkeypatch
):
    import app.notifications as notifications

    monkeypatch.setenv("RCA_NOTIFICATION_DEDUPE_SECONDS", "10")

    clock = [100.0]
    monkeypatch.setattr(notifications.time, "monotonic", lambda: clock[0])

    first = notifications.send_notification(sample_rca)

    clock[0] = 105.0
    second = notifications.send_notification(sample_rca)

    clock[0] = 111.0
    third = notifications.send_notification(sample_rca)

    assert first["status"] == "sent"
    assert second["status"] == "suppressed"
    assert third["status"] == "sent"
    assert len(get_notifications()) == 2


def test_zero_cooldown_disables_duplicate_suppression(
    sample_rca, monkeypatch
):
    import app.notifications as notifications

    monkeypatch.setenv("RCA_NOTIFICATION_DEDUPE_SECONDS", "0")

    first = notifications.send_notification(sample_rca)
    second = notifications.send_notification(sample_rca)

    assert first["status"] == "sent"
    assert second["status"] == "sent"
    assert len(get_notifications()) == 2


def test_critical_minimum_severity_filters_warning(
    sample_rca, monkeypatch
):
    import app.notifications as notifications

    monkeypatch.setenv("RCA_NOTIFICATION_MIN_SEVERITY", "critical")
    sample_rca["severity"] = "warning"

    result = notifications.send_notification(sample_rca)

    assert result["status"] == "skipped"
    assert result["filter"] == "severity"
    assert get_notifications() == []


def test_critical_alert_passes_critical_threshold(
    sample_rca, monkeypatch
):
    import app.notifications as notifications

    monkeypatch.setenv("RCA_NOTIFICATION_MIN_SEVERITY", "critical")
    sample_rca["severity"] = "critical"

    result = notifications.send_notification(sample_rca)

    assert result["status"] == "sent"
    assert len(get_notifications()) == 1


def test_severity_with_whitespace_is_normalized(sample_rca, monkeypatch):
    monkeypatch.setenv("RCA_NOTIFICATION_MIN_SEVERITY", "warning")
    sample_rca["severity"] = " critical "

    result = send_notification(sample_rca)

    assert result["status"] == "sent"
    assert len(get_notifications()) == 1


def test_invalid_minimum_severity_falls_back_to_warning(
    sample_rca, monkeypatch
):
    monkeypatch.setenv("RCA_NOTIFICATION_MIN_SEVERITY", "invalid")
    sample_rca["severity"] = "info"

    result = send_notification(sample_rca)

    assert result["status"] == "skipped"
    assert result["filter"] == "severity"
    assert get_notifications() == []


def test_invalid_dedupe_config_uses_default_cooldown(
    sample_rca, monkeypatch
):
    monkeypatch.setenv("RCA_NOTIFICATION_DEDUPE_SECONDS", "invalid")

    first = send_notification(sample_rca)
    second = send_notification(sample_rca)

    assert first["status"] == "sent"
    assert second["status"] == "suppressed"
    assert len(get_notifications()) == 1
