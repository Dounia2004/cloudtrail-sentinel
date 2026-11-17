from datetime import datetime, timedelta, timezone

from src.detection.rules import auth_001, auth_003, auth_004

BASE = datetime(2026, 11, 10, 9, 0, tzinfo=timezone.utc)


def stamp(minutes):
    return (BASE + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def by_id(events):
    return {e.event_id: e for e in events}


def login(make_event, mfa_used, result="Success", **extra):
    return make_event(
        event_name="ConsoleLogin",
        event_source="signin.amazonaws.com",
        login_result=result,
        mfa_used=mfa_used,
        **extra,
    )


# AUTH-001 -----------------------------------------------------------------


def test_auth_001_detects_logins_without_mfa_in_fixtures(fixture_events):
    alerts = auth_001.detect(fixture_events)
    events = by_id(fixture_events)
    assert len(alerts) == 3
    scenarios = {events[a.event_ids[0]].scenario for a in alerts}
    assert scenarios == {"credential_abuse", "no_mfa_login", "privilege_escalation"}
    assert all(a.mitre_technique == "T1078.004" and a.score == 50 for a in alerts)


def test_auth_001_detects_success_without_mfa(make_event):
    assert len(auth_001.detect([login(make_event, 0)])) == 1


def test_auth_001_ignores_login_with_mfa(make_event):
    assert auth_001.detect([login(make_event, 1)]) == []


def test_auth_001_ignores_failed_login(make_event):
    assert auth_001.detect([login(make_event, 0, result="Failure")]) == []


def test_auth_001_ignores_other_events(make_event):
    assert auth_001.detect([make_event(event_name="ListUsers", mfa_used=0)]) == []


# AUTH-004 -----------------------------------------------------------------


def test_auth_004_detects_root_usage(make_event):
    event = make_event(identity_type="Root", identity_name="root")
    alerts = auth_004.detect([event])
    assert len(alerts) == 1
    assert alerts[0].score == 80


def test_auth_004_detects_failed_root_attempt_too(make_event):
    event = make_event(identity_type="Root", identity_name="root", error_code="AccessDenied")
    assert len(auth_004.detect([event])) == 1


def test_auth_004_ignores_regular_users(make_event):
    assert auth_004.detect([make_event(identity_type="IAMUser")]) == []


def test_auth_004_silent_on_fixtures(fixture_events):
    assert auth_004.detect(fixture_events) == []


# AUTH-003 -----------------------------------------------------------------


def history(make_event, count, ip="203.0.113.11", identity="bob", start=0):
    return [
        make_event(
            event_id=f"{identity}-h{i}",
            event_time=stamp(start + i),
            identity_name=identity,
            source_ip=ip,
        )
        for i in range(count)
    ]


def test_auth_003_detects_new_ips_in_fixtures(fixture_events):
    alerts = auth_003.detect(fixture_events)
    events = by_id(fixture_events)
    assert len(alerts) == 6
    assert {a.identity for a in alerts} == {"alice", "bob", "carol", "dave"}
    assert all(events[a.event_ids[0]].is_attack == 1 for a in alerts)
    carol_ips = {events[a.event_ids[0]].source_ip for a in alerts if a.identity == "carol"}
    assert len(carol_ips) == 3
    assert "no_mfa_login" not in {events[a.event_ids[0]].scenario for a in alerts}


def test_auth_003_detects_new_ip_after_history(make_event):
    events = history(make_event, 5)
    events.append(make_event(event_id="new", event_time=stamp(10), source_ip="198.51.100.9"))
    alerts = auth_003.detect(events)
    assert len(alerts) == 1
    assert alerts[0].event_ids == ["new"]
    assert "198.51.100.9" in alerts[0].description


def test_auth_003_alerts_once_per_new_ip(make_event):
    events = history(make_event, 5)
    for i in range(3):
        events.append(
            make_event(event_id=f"n{i}", event_time=stamp(10 + i), source_ip="198.51.100.9")
        )
    assert len(auth_003.detect(events)) == 1


def test_auth_003_needs_enough_history(make_event):
    events = history(make_event, 3)
    events.append(make_event(event_id="new", event_time=stamp(10), source_ip="198.51.100.9"))
    assert auth_003.detect(events) == []


def test_auth_003_ignores_aws_service_addresses(make_event):
    events = history(make_event, 5)
    events.append(
        make_event(event_id="svc", event_time=stamp(10), source_ip="cloudformation.amazonaws.com")
    )
    assert auth_003.detect(events) == []


def test_auth_003_keeps_identities_separate(make_event):
    events = history(make_event, 5, ip="203.0.113.11", identity="bob")
    events += history(make_event, 5, ip="203.0.113.10", identity="alice")
    events.append(
        make_event(
            event_id="x", event_time=stamp(20), identity_name="bob", source_ip="203.0.113.10"
        )
    )
    alerts = auth_003.detect(events)
    assert len(alerts) == 1
    assert alerts[0].identity == "bob"
