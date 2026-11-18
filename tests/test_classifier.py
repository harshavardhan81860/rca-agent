def test_failed_scheduling():
    assert classify_incident(
        "FailedScheduling",
        "Insufficient cpu"
    ) == "Infrastructure"
