from pathlib import Path

import pytest

from src.detection.rules import iam_001
from src.ingestion.models import Event, load_events

FIXTURES = Path(__file__).parent / "fixtures"
ADMIN = '{"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "userName": "svc"}'


@pytest.fixture(scope="module")
def fixture_events():
    events, _ = load_events(
        FIXTURES / "cloudtrail_sample.json", FIXTURES / "labels_sample.csv"
    )
    return events


def make_event(name="AttachUserPolicy", params=ADMIN, error_code=None):
    return Event(
        event_id="e-1",
        event_time="2026-11-10T10:25:00Z",
        event_source="iam.amazonaws.com",
        event_name=name,
        aws_region="us-east-1",
        identity_type="IAMUser",
        identity_name="bob",
        source_ip="203.0.113.11",
        request_params=params,
        error_code=error_code,
    )


def test_detects_privilege_escalation_in_fixtures(fixture_events):
    alerts = iam_001.detect(fixture_events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "IAM-001"
    assert alert.mitre_technique == "T1098"
    assert alert.identity == "bob"
    assert alert.score == 80
    flagged = {e.event_id: e for e in fixture_events}[alert.event_ids[0]]
    assert flagged.scenario == "privilege_escalation"
    assert flagged.event_name == "AttachUserPolicy"


def test_no_alert_on_normal_activity(fixture_events):
    normal = [e for e in fixture_events if e.scenario == "normal"]
    assert iam_001.detect(normal) == []


def test_every_alert_points_to_a_real_attack(fixture_events):
    by_id = {e.event_id: e for e in fixture_events}
    for alert in iam_001.detect(fixture_events):
        assert all(by_id[event_id].is_attack == 1 for event_id in alert.event_ids)


def test_attach_role_policy_with_admin_triggers():
    params = '{"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "roleName": "r"}'
    alerts = iam_001.detect([make_event("AttachRolePolicy", params)])
    assert len(alerts) == 1
    assert "r" in alerts[0].description


def test_other_policy_does_not_trigger():
    params = '{"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess", "userName": "svc"}'
    assert iam_001.detect([make_event(params=params)]) == []


def test_failed_attempt_does_not_trigger():
    assert iam_001.detect([make_event(error_code="AccessDenied")]) == []


def test_invalid_request_params_are_ignored():
    assert iam_001.detect([make_event(params="not json")]) == []
    assert iam_001.detect([make_event(params=None)]) == []
