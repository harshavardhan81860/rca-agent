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
    ) == "Application"
