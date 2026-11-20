from app import main


def prepare_alert_test(monkeypatch):
    monkeypatch.setattr(
        main,
        "collect_prometheus_metrics",
        lambda *args, **kwargs: {},
    )


def test_unknown_alert_with_postgres_evidence_is_database(monkeypatch):
    prepare_alert_test(monkeypatch)

    alert = {
        "status": "firing",
        "labels": {
            "alertname": "UnknownDatabaseAlert",
            "severity": "warning",
        },
        "annotations": {
            "summary": "PostgreSQL connection failure",
            "description": "PostgreSQL DNS name resolution failed",
        },
    }

    result = main.analyze_alert(alert)

    assert result["category"] == "Database"

    details = result["classification_details"]

    assert details["category"] == "Database"
    assert details["failure_type"] == "Networking"
    assert details["confidence"] == "High"
    assert "postgresql" in details["matched_evidence"]
    assert "dns" in details["matched_evidence"]


def test_unknown_alert_with_generic_connection_error_is_networking(monkeypatch):
    prepare_alert_test(monkeypatch)

    alert = {
        "status": "firing",
        "labels": {
            "alertname": "UnknownConnectionAlert",
            "severity": "warning",
        },
        "annotations": {
            "summary": "Service connection failure",
            "description": "Connection refused",
        },
    }

    result = main.analyze_alert(alert)

    assert result["category"] == "Networking"
    assert result["classification_details"]["failure_type"] == "Networking"


def test_node_not_ready_keeps_infrastructure_category(monkeypatch):
    prepare_alert_test(monkeypatch)

    alert = {
        "status": "firing",
        "labels": {
            "alertname": "NodeNotReady",
            "severity": "critical",
        },
        "annotations": {
            "summary": "PostgreSQL node connectivity issue",
            "description": "Database connection refused",
        },
    }

    result = main.analyze_alert(alert)

    assert result["category"] == "Infrastructure"
    assert result["classification_details"] is None


def test_pod_not_ready_keeps_kubernetes_category(monkeypatch):
    prepare_alert_test(monkeypatch)

    alert = {
        "status": "firing",
        "labels": {
            "alertname": "PodNotReady",
            "severity": "warning",
        },
        "annotations": {
            "summary": "PostgreSQL pod readiness issue",
            "description": "Database connection refused",
        },
    }

    result = main.analyze_alert(alert)

    assert result["category"] == "Kubernetes"
    assert result["classification_details"] is None
