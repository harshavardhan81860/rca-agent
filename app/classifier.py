def analyze_classification(reason, message=""):
    reason = (reason or "").lower()
    message = (message or "").lower()
    evidence = f"{reason} {message}"

    database_terms = [
        "database", "postgres", "postgresql", "mysql",
        "mariadb", "mongodb", "mongo", "redis",
        "sqlstate", "connection pool", "too many connections",
    ]

    network_terms = [
        "dns", "connection timed out", "connection timeout",
        "connection refused", "network unreachable",
        "network is unreachable", "no route to host",
        "name resolution failed", "service unavailable",
    ]

    storage_terms = [
        "persistentvolumeclaim", "failedmount", "volume mount",
        "failed attach", "mountvolume", "persistentvolume",
        "volume is not attached",
    ]

    security_terms = [
        "forbidden", "unauthorized", "rbac",
        "permission denied", "access denied",
        "authentication failed",
    ]

    infrastructure_terms = [
        "insufficient cpu", "insufficient memory",
        "too many pods", "failedscheduling",
        "node notready", "node not ready",
        "nodepressure", "diskpressure", "memorypressure",
    ]

    application_terms = [
        "crashloopbackoff", "oomkilled",
        "imagepullbackoff", "errimagepull",
        "application exception", "application error",
        "container exited", "non-zero exit", "exit code",
        "liveness probe failed", "readiness probe failed",
        "startup probe failed", "traceback",
    ]

    def matched(terms):
        return [term for term in terms if term in evidence]

    database_matches = matched(database_terms)
    network_matches = matched(network_terms)
    storage_matches = matched(storage_terms)
    security_matches = matched(security_terms)
    infrastructure_matches = matched(infrastructure_terms)
    application_matches = matched(application_terms)

    # Identify the affected component.
    # Explicit database context takes priority over generic network errors.
    if database_matches:
        category = "Database"
    elif storage_matches:
        category = "Storage"
    elif security_matches:
        category = "Security"
    elif infrastructure_matches:
        category = "Infrastructure"
    elif application_matches:
        category = "Application"
    elif network_matches:
        category = "Networking"
    else:
        category = "Unknown"

    # Identify the failure mechanism separately.
    if network_matches:
        failure_type = "Networking"
        probable_cause = (
            "A network connection or DNS resolution problem "
            "may be preventing communication with the affected service."
        )
    elif storage_matches:
        failure_type = "Storage"
        probable_cause = (
            "A persistent volume or storage attachment/mount problem "
            "may be preventing the workload from accessing its storage."
        )
    elif security_matches:
        failure_type = "Security"
        probable_cause = (
            "An authentication, authorization, or RBAC permission "
            "problem may be blocking the operation."
        )
    elif infrastructure_matches:
        failure_type = "Infrastructure"
        probable_cause = (
            "A Kubernetes node, scheduling, or resource-capacity "
            "problem may be affecting the workload."
        )
    elif database_matches:
        failure_type = "Database"
        probable_cause = (
            "A database connection, capacity, or database-service "
            "problem may be affecting the application."
        )
    elif application_matches:
        failure_type = "Application"
        probable_cause = (
            "An application or container execution problem "
            "may be affecting the workload."
        )
    else:
        failure_type = "Unknown"
        probable_cause = (
            "There is not enough matching evidence to identify "
            "the failure mechanism."
        )

    matched_evidence = list(dict.fromkeys(
        database_matches
        + network_matches
        + storage_matches
        + security_matches
        + infrastructure_matches
        + application_matches
    ))

    # This is a rule-based estimate, not a statistical probability.
    if category != "Unknown" and len(matched_evidence) >= 2:
        confidence = "High"
    elif category != "Unknown":
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "category": category,
        "failure_type": failure_type,
        "confidence": confidence,
        "matched_evidence": matched_evidence,
        "probable_cause": probable_cause,
    }


def classify_incident(reason, message=""):
    # Preserve the original string-returning interface.
    return analyze_classification(reason, message)["category"]
