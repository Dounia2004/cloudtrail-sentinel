from pathlib import Path

from src.detection.engine import run_rules
from src.ingestion.models import load_events

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture_events():
    events, _ = load_events(
        FIXTURES / "cloudtrail_sample.json", FIXTURES / "labels_sample.csv"
    )
    return events


def test_run_rules_finds_alerts_in_fixtures():
    alerts = run_rules(load_fixture_events())
    assert len(alerts) >= 1
    assert {alert.rule_id for alert in alerts} <= {"IAM-001"}


def test_alerts_are_sorted_by_time():
    alerts = run_rules(load_fixture_events())
    times = [alert.first_seen for alert in alerts]
    assert times == sorted(times)
