from pathlib import Path

from src.ingestion.models import load_events

FIXTURES = Path(__file__).parent / "fixtures"
LOGS = FIXTURES / "cloudtrail_sample.json"
LABELS = FIXTURES / "labels_sample.csv"

EXPECTED_SCENARIOS = {
    "normal",
    "privilege_escalation",
    "credential_abuse",
    "iam_recon",
    "defense_evasion",
    "s3_exfiltration",
    "no_mfa_login",
    "persistence_access_key",
}


def test_fixture_files_exist():
    assert LOGS.exists()
    assert LABELS.exists()


def test_fixtures_pass_validation():
    events, rejected = load_events(LOGS, LABELS)
    assert rejected == []
    assert len(events) > 0


def test_fixtures_cover_every_scenario():
    events, _ = load_events(LOGS, LABELS)
    assert {e.scenario for e in events} == EXPECTED_SCENARIOS


def test_fixtures_stay_small():
    events, _ = load_events(LOGS, LABELS)
    assert len(events) < 200
