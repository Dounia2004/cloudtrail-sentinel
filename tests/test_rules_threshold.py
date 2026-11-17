from datetime import datetime, timedelta, timezone

from src.detection.rules import auth_002, iam_006, s3_001
from src.detection.rules.common import find_bursts, group_by_identity

BASE = datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)


def stamp(minutes=0, seconds=0):
    when = BASE + timedelta(minutes=minutes, seconds=seconds)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def series(make_event, times, **fields):
    """Crée un événement par date de `times` (liste de (minutes, secondes))."""
    return [
        make_event(event_id=f"e-{i}", event_time=stamp(*t), **fields)
        for i, t in enumerate(times)
    ]


def by_id(events):
    return {e.event_id: e for e in events}


# Fenêtre glissante --------------------------------------------------------


def test_find_bursts_detects_a_burst(make_event):
    events = series(make_event, [(i, 0) for i in range(5)])
    bursts = find_bursts(events, timedelta(minutes=5), 5)
    assert len(bursts) == 1
    assert len(bursts[0]) == 5


def test_find_bursts_ignores_spread_out_events(make_event):
    events = series(make_event, [(i * 10, 0) for i in range(5)])
    assert find_bursts(events, timedelta(minutes=5), 5) == []


def test_find_bursts_separates_two_bursts(make_event):
    times = [(i, 0) for i in range(3)] + [(60 + i, 0) for i in range(3)]
    bursts = find_bursts(series(make_event, times), timedelta(minutes=5), 3)
    assert len(bursts) == 2


def test_group_by_identity_sorts_each_group(make_event):
    late = make_event(event_id="e-1", event_time=stamp(5), identity_name="bob")
    early = make_event(event_id="e-2", event_time=stamp(1), identity_name="bob")
    other = make_event(event_id="e-3", event_time=stamp(2), identity_name="alice")
    groups = group_by_identity([late, early, other])
    assert [e.event_id for e in groups["bob"]] == ["e-2", "e-1"]
    assert len(groups["alice"]) == 1


# IAM-006 ------------------------------------------------------------------

RECON_NAMES = ["ListUsers", "ListRoles", "ListPolicies", "ListGroups", "GetAccountSummary"]


def recon_events(make_event, names, step_seconds=20):
    return [
        make_event(
            event_id=f"e-{i}", event_time=stamp(0, i * step_seconds), event_name=name
        )
        for i, name in enumerate(names)
    ]


def test_iam_006_detects_recon_in_fixtures(fixture_events):
    alerts = iam_006.detect(fixture_events)
    assert len(alerts) == 1
    alert = alerts[0]
    events = by_id(fixture_events)
    assert alert.identity == "dave"
    assert len(alert.event_ids) == 8
    assert all(events[i].scenario == "iam_recon" for i in alert.event_ids)
    assert alert.mitre_technique == "T1087.004"


def test_iam_006_detects_distinct_calls(make_event):
    assert len(iam_006.detect(recon_events(make_event, RECON_NAMES))) == 1


def test_iam_006_ignores_repeated_single_call(make_event):
    assert iam_006.detect(recon_events(make_event, ["ListUsers"] * 6)) == []


def test_iam_006_ignores_slow_calls(make_event):
    assert iam_006.detect(recon_events(make_event, RECON_NAMES, step_seconds=300)) == []


def test_iam_006_does_not_mix_identities(make_event):
    events = []
    for i, name in enumerate(RECON_NAMES):
        who = "alice" if i % 2 == 0 else "bob"
        events.append(
            make_event(
                event_id=f"e-{i}", event_time=stamp(0, i * 10), event_name=name,
                identity_name=who,
            )
        )
    assert iam_006.detect(events) == []


# AUTH-002 -----------------------------------------------------------------


def login(make_event, index, minutes, result):
    return make_event(
        event_id=f"e-{index}",
        event_time=stamp(minutes),
        event_name="ConsoleLogin",
        event_source="signin.amazonaws.com",
        login_result=result,
    )


def test_auth_002_detects_brute_force_in_fixtures(fixture_events):
    alerts = auth_002.detect(fixture_events)
    assert len(alerts) == 1
    alert = alerts[0]
    events = by_id(fixture_events)
    assert alert.identity == "carol"
    assert len(alert.event_ids) == 7
    assert all(events[i].scenario == "credential_abuse" for i in alert.event_ids)
    assert alert.mitre_technique == "T1110"


def test_auth_002_detects_failures_then_success(make_event):
    events = [login(make_event, i, i, "Failure") for i in range(5)]
    events.append(login(make_event, 5, 7, "Success"))
    assert len(auth_002.detect(events)) == 1


def test_auth_002_needs_a_success(make_event):
    events = [login(make_event, i, i, "Failure") for i in range(6)]
    assert auth_002.detect(events) == []


def test_auth_002_needs_enough_failures(make_event):
    events = [login(make_event, i, i, "Failure") for i in range(4)]
    events.append(login(make_event, 4, 5, "Success"))
    assert auth_002.detect(events) == []


def test_auth_002_ignores_late_success(make_event):
    events = [login(make_event, i, i, "Failure") for i in range(5)]
    events.append(login(make_event, 5, 60, "Success"))
    assert auth_002.detect(events) == []


# S3-001 -------------------------------------------------------------------


def reads(make_event, count, step_seconds):
    return [
        make_event(
            event_id=f"e-{i}",
            event_time=stamp(0, i * step_seconds),
            event_name="GetObject",
            event_source="s3.amazonaws.com",
        )
        for i in range(count)
    ]


def test_s3_001_detects_mass_reads_in_fixtures(fixture_events):
    alerts = s3_001.detect(fixture_events)
    assert len(alerts) == 1
    alert = alerts[0]
    events = by_id(fixture_events)
    assert alert.identity == "carol"
    assert len(alert.event_ids) == 15
    assert all(events[i].scenario == "s3_exfiltration" for i in alert.event_ids)
    assert alert.mitre_technique == "T1530"


def test_s3_001_detects_ten_reads_in_a_few_minutes(make_event):
    assert len(s3_001.detect(reads(make_event, 10, 20))) == 1


def test_s3_001_ignores_nine_reads(make_event):
    assert s3_001.detect(reads(make_event, 9, 20)) == []


def test_s3_001_ignores_slow_reads(make_event):
    assert s3_001.detect(reads(make_event, 10, 1200)) == []
