from app.classifier import analyze_classification


def test_postgres_dns_failure_separates_component_and_failure():
    result = analyze_classification(
        "PostgreSQLConnectionError",
        "PostgreSQL DNS name resolution failed",
    )

    assert result["category"] == "Database"
    assert result["failure_type"] == "Networking"
    assert result["confidence"] == "High"
    assert "postgresql" in result["matched_evidence"]
    assert "dns" in result["matched_evidence"]


def test_database_connection_pool_failure():
    result = analyze_classification(
        "DatabaseError",
        "MySQL connection pool exhausted",
    )

    assert result["category"] == "Database"
    assert result["failure_type"] == "Database"


def test_generic_dns_failure():
    result = analyze_classification(
        "DNSFailure",
        "DNS name resolution failed",
    )

    assert result["category"] == "Networking"
    assert result["failure_type"] == "Networking"


def test_storage_failure():
    result = analyze_classification(
        "FailedMount",
        "PersistentVolumeClaim could not be mounted",
    )

    assert result["category"] == "Storage"
    assert result["failure_type"] == "Storage"


def test_security_failure():
    result = analyze_classification(
        "AccessDenied",
        "Kubernetes RBAC forbidden",
    )

    assert result["category"] == "Security"
    assert result["failure_type"] == "Security"


def test_application_failure():
    result = analyze_classification(
        "CrashLoopBackOff",
        "Container repeatedly restarting",
    )

    assert result["category"] == "Application"
    assert result["failure_type"] == "Application"


def test_unknown_failure_has_low_confidence():
    result = analyze_classification(
        "UnexpectedIncident",
        "Something unusual happened",
    )

    assert result["category"] == "Unknown"
    assert result["failure_type"] == "Unknown"
    assert result["confidence"] == "Low"
    assert result["matched_evidence"] == []
