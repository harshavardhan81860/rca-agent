
def classify_incident(reason, message=""):
    reason = (reason or "").lower()
    message = (message or "").lower()
    evidence = reason + " " + message

    if any(x in evidence for x in [
        "insufficient cpu",
        "insufficient memory",
        "too many pods",
        "node notready",
        "node not ready"
    ]):
        return "Infrastructure"

    if any(x in evidence for x in [
        "persistentvolumeclaim",
        "failedmount",
        "volume mount",
        "failed attach"
    ]):
        return "Storage"

    if any(x in evidence for x in [
        "dns",
        "connection timed out",
        "network unreachable",
        "connection refused"
    ]):
        return "Networking"

    if any(x in evidence for x in [
        "forbidden",
        "unauthorized",
        "rbac"
    ]):
        return "Security"

    if any(x in evidence for x in [
        "database",
        "postgres",
        "mysql",
        "connection pool"
    ]):
        return "Database"

    if any(x in evidence for x in [
        "crashloopbackoff",
        "oomkilled",
        "imagepullbackoff",
        "application exception"
    ]):
        return "Application"

    return "Unknown"
