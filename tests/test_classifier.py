from app.classifier import classify_incident


def test_failed_scheduling():
    assert classify_incident(
        "FailedScheduling",
        "Insufficient cpu"
    ) == "Infrastructure"


def test_oom_killed():
    assert classify_incident(
        "OOMKilled",
        "Container was terminated due to memory exhaustion"
    ) == "Application"


def test_crash_loop_backoff():
    assert classify_incident(
        "CrashLoopBackOff",
        "Container repeatedly restarting"
    ) == "Application"


def test_image_pull_failure():
    assert classify_incident(
        "ImagePullBackOff",
        "Image tag not found"
    ) == "Infrastructure"


def test_database_postgres_connection_failure():
    assert classify_incident(
        "DatabaseConnectionError",
        "PostgreSQL connection refused"
    ) == "Database"


def test_mysql_connection_pool_exhausted():
    assert classify_incident(
        "DatabaseError",
        "MySQL connection pool exhausted"
    ) == "Database"


def test_generic_connection_refused():
    assert classify_incident(
        "ServiceConnectionError",
        "Connection refused"
    ) == "Networking"


def test_dns_failure():
    assert classify_incident(
        "DNSFailure",
        "DNS name resolution failed"
    ) == "Networking"


def test_persistent_volume_failure():
    assert classify_incident(
        "FailedMount",
        "PersistentVolumeClaim could not be mounted"
    ) == "Storage"


def test_rbac_forbidden():
    assert classify_incident(
        "AccessDenied",
        "Kubernetes RBAC forbidden"
    ) == "Security"


def test_application_exception():
    assert classify_incident(
        "ApplicationFailure",
        "Unhandled application exception"
    ) == "Application"


def test_unknown_incident():
    assert classify_incident(
        "SomethingUnexpected",
        "No matching evidence"
    ) == "Unknown"
