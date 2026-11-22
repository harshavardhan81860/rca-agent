import pytest
from fastapi.testclient import TestClient

from app import main


client = TestClient(main.app)


@pytest.fixture
def mock_external_investigations(monkeypatch):
    """Prevent tests from contacting Kubernetes or Prometheus."""

    monkeypatch.setattr(
        main,
        "investigate_pod",
        lambda *args, **kwargs: {
            "status": "error",
            "error": "Simulated pod investigation",
        },
    )

    monkeypatch.setattr(
        main,
        "investigate_node",
        lambda *args, **kwargs: {
            "status": "error",
            "error": "Simulated node investigation",
        },
    )

    monkeypatch.setattr(
        main,
        "investigate_deployment",
        lambda *args, **kwargs: {
            "status": "error",
            "error": "Simulated deployment investigation",
        },
    )

    monkeypatch.setattr(
        main,
        "collect_prometheus_metrics",
        lambda *args, **kwargs: {},
    )

    monkeypatch.setattr(
        main,
        "analyze_deployment_capacity",
        lambda *args, **kwargs: {},
    )


SIMULATED_ALERTS = [
    (
        "application_crash",
        "PodCrashLooping",
        "Container repeatedly restarting after exit code 1",
        "Application",
    ),
    (
        "database_connection_failure",
        "PostgreSQLConnectionError",
        "PostgreSQL connection pool exhausted. Application cannot connect to PostgreSQL.",
        "Database",
    ),
    (
        "dns_resolution_failure",
        "DNSResolutionFailure",
        "DNS name resolution failed while connecting to the service.",
        "Networking",
    ),
    (
        "node_not_ready",
        "NodeNotReady",
        "Kubernetes node not ready.",
        "Infrastructure",
    ),
    (
        "storage_mount_failure",
        "FailedMount",
        "PersistentVolumeClaim volume mount failed.",
        "Storage",
    ),
    (
        "image_pull_failure",
        "ImagePullBackOff",
        "Container image pull failed with ErrImagePull.",
        "Infrastructure",
    ),
]


@pytest.mark.parametrize(
    "scenario, alert_name, summary, expected_category",
    SIMULATED_ALERTS,
)
def test_webhook_processes_simulated_alerts(
    mock_external_investigations,
    scenario,
    alert_name,
    summary,
    expected_category,
):
    payload = {
        "receiver": "rca-agent-test",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": alert_name,
                    "severity": "warning",
                    "namespace": "test-namespace",
                    "pod": "test-pod",
                    "node": "test-node",
                },
                "annotations": {
                    "summary": summary,
                    "description": f"Simulated {scenario} incident for integration testing.",
                },
                "startsAt": "2026-11-23T10:00:00Z",
            }
        ],
    }

    response = client.post("/webhook/alerts", json=payload)

    assert response.status_code == 200

    body = response.json()
    assert body["message"] == "Alertmanager webhook received"
    assert body["receiver"] == "rca-agent-test"
    assert body["alerts_received"] == 1

    result = body["analysis"][0]
    assert result["alertname"] == alert_name
    assert result["status"] == "firing"

    rca = result["analysis"]
    assert rca["alert_name"] == alert_name
    assert rca["category"] == expected_category
    assert rca["classification_details"]["category"] == expected_category
    assert rca["probable_cause"]
    assert isinstance(rca["investigation"], dict)

    # The agent must never automatically change workloads.
    assert rca["remediation"]["automatic_action"] is False


def test_webhook_skips_resolved_alerts(monkeypatch):
    def unexpected_investigation(alert):
        pytest.fail("Resolved alerts must not trigger RCA investigation")

    monkeypatch.setattr(main, "analyze_alert", unexpected_investigation)

    payload = {
        "receiver": "rca-agent-test",
        "status": "resolved",
        "alerts": [
            {
                "status": "resolved",
                "labels": {
                    "alertname": "PodCrashLooping",
                    "namespace": "test-namespace",
                    "pod": "test-pod",
                },
            }
        ],
    }

    response = client.post("/webhook/alerts", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["alerts_received"] == 1
    assert body["analysis"][0]["status"] == "resolved"
    assert "skipped" in body["analysis"][0]["message"].lower()


def test_webhook_processes_multiple_alerts(mock_external_investigations):
    payload = {
        "receiver": "rca-agent-test",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "PostgreSQLConnectionError",
                    "severity": "critical",
                },
                "annotations": {
                    "summary": "PostgreSQL connection refused",
                },
            },
            {
                "status": "resolved",
                "labels": {
                    "alertname": "DNSResolutionFailure",
                },
            },
        ],
    }

    response = client.post("/webhook/alerts", json=payload)

    assert response.status_code == 200

    body = response.json()
    assert body["alerts_received"] == 2
    assert body["analysis"][0]["status"] == "firing"
    assert body["analysis"][0]["analysis"]["category"] == "Database"
    assert body["analysis"][0]["analysis"]["remediation"]["automatic_action"] is False
    assert body["analysis"][1]["status"] == "resolved"
    assert "skipped" in body["analysis"][1]["message"].lower()


def test_webhook_accepts_empty_alert_list():
    response = client.post(
        "/webhook/alerts",
        json={
            "receiver": "rca-agent-test",
            "status": "firing",
            "alerts": [],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["alerts_received"] == 0
    assert body["analysis"] == []


def test_webhook_rejects_invalid_payload():
    response = client.post(
        "/webhook/alerts",
        json={"receiver": "rca-agent-test", "alerts": "not-a-list"},
    )

    assert response.status_code == 422
