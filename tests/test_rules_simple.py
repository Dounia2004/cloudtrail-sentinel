import json

from src.detection.rules import iam_002, iam_003, iam_004, iam_005, log_001


def only(events, scenario):
    return [e for e in events if e.scenario == scenario]


def by_id(events):
    return {e.event_id: e for e in events}


# LOG-001 -------------------------------------------------------------------


def test_log_001_detects_logging_shutdown_in_fixtures(fixture_events):
    alerts = log_001.detect(fixture_events)
    assert len(alerts) == 2
    events = by_id(fixture_events)
    assert {a.identity for a in alerts} == {"alice"}
    assert {events[a.event_ids[0]].event_name for a in alerts} == {"StopLogging", "DeleteTrail"}
    assert all(events[a.event_ids[0]].scenario == "defense_evasion" for a in alerts)
    assert all(a.mitre_technique == "T1562.008" and a.score == 95 for a in alerts)


def test_log_001_ignores_failed_attempt(make_event):
    event = make_event(event_name="StopLogging", error_code="AccessDenied")
    assert log_001.detect([event]) == []


def test_log_001_detects_update_trail(make_event):
    event = make_event(event_name="UpdateTrail", request_params=json.dumps({"name": "main"}))
    assert len(log_001.detect([event])) == 1


# IAM-002 -------------------------------------------------------------------


def test_iam_002_detects_default_policy_version(make_event):
    params = {"policyArn": "arn:aws:iam::123456789012:policy/p", "setAsDefault": True}
    event = make_event(event_name="CreatePolicyVersion", request_params=json.dumps(params))
    alerts = iam_002.detect([event])
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1098"


def test_iam_002_accepts_string_true(make_event):
    params = {"policyArn": "p", "setAsDefault": "true"}
    event = make_event(event_name="CreatePolicyVersion", request_params=json.dumps(params))
    assert len(iam_002.detect([event])) == 1


def test_iam_002_ignores_non_default_version(make_event):
    params = {"policyArn": "p", "setAsDefault": False}
    event = make_event(event_name="CreatePolicyVersion", request_params=json.dumps(params))
    assert iam_002.detect([event]) == []


def test_iam_002_silent_on_fixtures(fixture_events):
    assert iam_002.detect(fixture_events) == []


# IAM-003 -------------------------------------------------------------------


def test_iam_003_detects_inline_policies(make_event):
    user = make_event(
        event_name="PutUserPolicy",
        request_params=json.dumps({"userName": "svc", "policyName": "p1"}),
    )
    role = make_event(
        event_id="e-2",
        event_name="PutRolePolicy",
        request_params=json.dumps({"roleName": "r", "policyName": "p2"}),
    )
    alerts = iam_003.detect([user, role])
    assert len(alerts) == 2
    assert "p1" in alerts[0].description


def test_iam_003_ignores_other_events(make_event):
    assert iam_003.detect([make_event(event_name="ListUsers")]) == []


# IAM-004 -------------------------------------------------------------------


def test_iam_004_detects_key_for_another_user_in_fixtures(fixture_events):
    alerts = iam_004.detect(fixture_events)
    assert len(alerts) == 1
    flagged = by_id(fixture_events)[alerts[0].event_ids[0]]
    assert flagged.scenario == "persistence_access_key"
    assert alerts[0].identity == "carol"
    assert "alice" in alerts[0].description
    assert alerts[0].mitre_technique == "T1098.001"


def test_iam_004_ignores_key_for_self(make_event):
    event = make_event(
        event_name="CreateAccessKey", request_params=json.dumps({"userName": "bob"})
    )
    assert iam_004.detect([event]) == []


def test_iam_004_ignores_request_without_user_name(make_event):
    assert iam_004.detect([make_event(event_name="CreateAccessKey")]) == []


# IAM-005 -------------------------------------------------------------------


def test_iam_005_detects_account_creation_in_fixtures(fixture_events):
    alerts = iam_005.detect(fixture_events)
    events = by_id(fixture_events)
    assert len(alerts) == 2
    scenarios = {events[a.event_ids[0]].scenario for a in alerts}
    assert scenarios == {"privilege_escalation", "persistence_access_key"}
    assert all(a.mitre_technique == "T1136.003" for a in alerts)


def test_iam_005_ignores_failed_call(make_event):
    event = make_event(event_name="CreateUser", error_code="AccessDenied")
    assert iam_005.detect([event]) == []
