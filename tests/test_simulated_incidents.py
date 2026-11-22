import pytest

from app.classifier import analyze_classification


@pytest.mark.parametrize(
    "scenario, alert_name, evidence, expected_category, expected_failure_type, required_evidence",
    [
        (
            "application_crash",
            "CrashLoopBackOff",
            "Container repeatedly restarting after exit code 1",
            "Application",
            "Application",
            ["crashloopbackoff", "exit code"],
        ),
        (
            "database_connection_failure",
            "PostgreSQLConnectionError",
            "PostgreSQL connection pool exhausted",
            "Database",
            "Database",
            ["postgresql", "connection pool"],
        ),
        (
            "dns_resolution_failure",
            "DNSResolutionFailure",
            "DNS name resolution failed",
            "Networking",
            "Networking",
            ["dns", "name resolution failed"],
        ),
        (
            "node_not_ready",
            "NodeNotReady",
            "Kubernetes node not ready",
            "Infrastructure",
            "Infrastructure",
            ["node not ready"],
        ),
        (
            "pvc_mount_failure",
            "FailedMount",
            "PersistentVolumeClaim volume mount failed",
            "Storage",
            "Storage",
            ["failedmount", "persistentvolumeclaim"],
        ),
        (
            "image_pull_failure",
            "ImagePullBackOff",
            "Container image pull failed with ErrImagePull",
            "Infrastructure",
            "Infrastructure",
            ["imagepullbackoff", "errimagepull"],
        ),
    ],
)
def test_simulated_incident_classification(
    scenario,
    alert_name,
    evidence,
    expected_category,
    expected_failure_type,
    required_evidence,
):
    result = analyze_classification(alert_name, evidence)

    assert result["category"] == expected_category, (
        f"{scenario}: expected category {expected_category}, "
        f"got {result['category']}"
    )

    assert result["failure_type"] == expected_failure_type, (
        f"{scenario}: expected failure type {expected_failure_type}, "
        f"got {result['failure_type']}"
    )

    assert result["confidence"] in ("High", "Medium")
    assert result["probable_cause"]
    assert result["matched_evidence"]

    for term in required_evidence:
        assert term in result["matched_evidence"], (
            f"{scenario}: missing expected evidence {term!r}; "
            f"matched {result['matched_evidence']}"
        )


def test_simulated_incidents_do_not_trigger_automatic_remediation():
    # The classifier only returns diagnostic information. It has no
    # Kubernetes mutation or remediation capability.
    result = analyze_classification(
        "CrashLoopBackOff",
        "Container repeatedly restarting after exit code 1",
    )

    assert "automatic_action" not in result
