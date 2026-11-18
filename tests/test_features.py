import pandas as pd
import pytest

from src.detection.ml.features import (
    FEATURE_COLUMNS,
    LABEL_COLUMNS,
    build_features,
)

ATTACK_SCENARIOS = {
    "privilege_escalation",
    "credential_abuse",
    "iam_recon",
    "defense_evasion",
    "s3_exfiltration",
    "no_mfa_login",
    "persistence_access_key",
}


def at(hour, minute=0, day=10):
    return f"2026-11-{day:02d}T{hour:02d}:{minute:02d}:00Z"


def make_events(make_event, specs):
    """specs : liste de dictionnaires ; un identifiant unique est ajouté à chaque événement."""
    return [make_event(event_id=f"e-{i}", **spec) for i, spec in enumerate(specs)]


def window_row(features, identity, hour):
    rows = features[(features["identity"] == identity) & (features["hour"] == hour)]
    assert len(rows) == 1
    return rows.iloc[0]


def test_one_row_per_identity_and_window(make_event):
    events = make_events(make_event, [
        {"event_time": at(10, 5)},
        {"event_time": at(10, 50)},
        {"event_time": at(11, 10)},
        {"event_time": at(10, 15), "identity_name": "alice"},
    ])
    features = build_features(events)
    assert len(features) == 3
    assert window_row(features, "bob", 10)["n_events"] == 2


def test_counts_inside_a_window(make_event):
    events = make_events(make_event, [
        {"event_time": at(10, 0), "event_name": "GetObject", "event_source": "s3.amazonaws.com"},
        {"event_time": at(10, 10), "event_name": "GetObject", "event_source": "s3.amazonaws.com"},
        {"event_time": at(10, 20), "event_name": "ListUsers", "error_code": "AccessDenied"},
    ])
    row = window_row(build_features(events), "bob", 10)
    assert row["n_events"] == 3
    assert row["n_s3_read"] == 2
    assert row["n_iam_read"] == 1
    assert row["n_errors"] == 1
    assert row["error_rate"] == pytest.approx(1 / 3)
    assert row["n_event_types"] == 2
    assert row["n_services"] == 2


def test_iam_writes_are_separated_from_reads(make_event):
    events = make_events(make_event, [
        {"event_time": at(10, 0), "event_name": "CreateUser"},
        {"event_time": at(10, 1), "event_name": "AttachUserPolicy"},
        {"event_time": at(10, 2), "event_name": "ListUsers"},
    ])
    row = window_row(build_features(events), "bob", 10)
    assert row["n_iam_write"] == 2
    assert row["n_iam_read"] == 1


def test_login_features(make_event):
    login = {"event_name": "ConsoleLogin", "event_source": "signin.amazonaws.com"}
    events = make_events(make_event, [
        {**login, "event_time": at(10, 0), "login_result": "Failure", "mfa_used": 0},
        {**login, "event_time": at(10, 1), "login_result": "Failure", "mfa_used": 0},
        {**login, "event_time": at(10, 2), "login_result": "Success", "mfa_used": 0},
        {**login, "event_time": at(10, 3), "login_result": "Success", "mfa_used": 1},
    ])
    row = window_row(build_features(events), "bob", 10)
    assert row["n_login_failures"] == 2
    assert row["n_login_no_mfa"] == 1


def test_new_ip_needs_history(make_event):
    events = make_events(make_event, [
        {"event_time": at(9, 0), "source_ip": "203.0.113.11"},
        {"event_time": at(10, 0), "source_ip": "198.51.100.9"},
        {"event_time": at(10, 30), "source_ip": "198.51.100.9"},
        {"event_time": at(11, 0), "source_ip": "198.51.100.9"},
    ])
    features = build_features(events)
    assert window_row(features, "bob", 9)["n_new_ips"] == 0
    assert window_row(features, "bob", 10)["n_new_ips"] == 1
    assert window_row(features, "bob", 11)["n_new_ips"] == 0


def test_regions(make_event):
    specs = [{"event_time": at(9, i)} for i in range(5)]
    specs.append({"event_time": at(9, 30), "aws_region": "eu-central-1"})
    row = window_row(build_features(make_events(make_event, specs)), "bob", 9)
    assert row["n_distinct_regions"] == 2
    assert row["n_off_region_events"] == 1


def test_time_features(make_event):
    events = make_events(make_event, [{"event_time": at(10, 0, day=14)}])  # un samedi
    row = window_row(build_features(events), "bob", 10)
    assert row["is_weekend"] == 1
    events = make_events(make_event, [{"event_time": at(10, 0, day=10)}])  # un mardi
    assert window_row(build_features(events), "bob", 10)["is_weekend"] == 0


def test_window_size_is_a_parameter(make_event):
    events = make_events(make_event, [{"event_time": at(9)}, {"event_time": at(15)}])
    assert len(build_features(events, window="1h")) == 2
    assert len(build_features(events, window="1D")) == 1


def test_labels(make_event):
    events = make_events(make_event, [
        {"event_time": at(9), "scenario": "normal", "is_attack": 0},
        {"event_time": at(10), "scenario": "iam_recon", "is_attack": 1},
        {"event_time": at(11), "scenario": "benign_backup_job", "is_attack": 0},
    ])
    features = build_features(events)
    assert window_row(features, "bob", 9)["scenario"] == "normal"
    attack = window_row(features, "bob", 10)
    assert attack["is_attack"] == 1 and attack["scenario"] == "iam_recon"
    assert attack["n_attack_events"] == 1
    benign = window_row(features, "bob", 11)
    assert benign["is_attack"] == 0 and benign["scenario"] == "benign_backup_job"


def test_empty_input_gives_empty_table():
    features = build_features([])
    assert features.empty
    assert set(FEATURE_COLUMNS) <= set(features.columns)


def test_labels_are_never_features():
    assert set(FEATURE_COLUMNS).isdisjoint(LABEL_COLUMNS)


def test_features_on_fixtures(fixture_events):
    features = build_features(fixture_events)
    assert not features[FEATURE_COLUMNS].isna().any().any()
    attack_scenarios = set(features.loc[features["is_attack"] == 1, "scenario"])
    assert attack_scenarios == ATTACK_SCENARIOS
    exfiltration = features[features["scenario"] == "s3_exfiltration"]
    assert exfiltration["n_s3_read"].max() >= 10
    assert isinstance(features["window_start"].iloc[0], pd.Timestamp)
