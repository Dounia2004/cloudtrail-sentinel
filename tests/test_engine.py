from src.detection.engine import run_rules

EXPECTED_RULES = {
    "IAM-001", "IAM-004", "IAM-005", "IAM-006", "LOG-001", "AUTH-002", "S3-001",
}


def test_run_rules_finds_expected_rules_in_fixtures(fixture_events):
    alerts = run_rules(fixture_events)
    assert {alert.rule_id for alert in alerts} == EXPECTED_RULES
    assert len(alerts) == 9


def test_alerts_are_sorted_by_time(fixture_events):
    times = [alert.first_seen for alert in run_rules(fixture_events)]
    assert times == sorted(times)


def test_no_alert_on_normal_activity(fixture_events):
    normal = [e for e in fixture_events if e.scenario == "normal"]
    assert run_rules(normal) == []


def test_every_alert_points_to_a_real_attack(fixture_events):
    by_id = {e.event_id: e for e in fixture_events}
    for alert in run_rules(fixture_events):
        assert all(by_id[event_id].is_attack == 1 for event_id in alert.event_ids)
