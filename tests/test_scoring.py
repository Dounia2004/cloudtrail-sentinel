from dataclasses import dataclass

import pandas as pd

from src.scoring.correlation import correlate, timeline
from src.scoring.scoring import build_alerts, severity, window_scores


@dataclass
class FakeAlert:
    identity: str
    rule_id: str
    first_seen: str
    last_seen: str
    score: int = 70
    mitre_technique: str = "T1098"
    description: str = "test"


def _windows() -> pd.DataFrame:
    hours = pd.date_range("2026-11-10 09:00", periods=3, freq="1h", tz="UTC")
    return pd.DataFrame({"identity": ["alice"] * 3, "window_start": hours})


def _ml(values) -> pd.Series:
    return pd.Series(values, index=range(3))


def test_rule_only_keeps_rule_score():
    a = FakeAlert("alice", "IAM-001", "2026-11-10T10:10:00Z", "2026-11-10T10:20:00Z")
    s = window_scores(_windows(), [a], _ml([0, 0, 0]))
    assert s["risk_score"].tolist() == [0, 70, 0]


def test_ml_only_scales_to_100_without_cap():
    s = window_scores(_windows(), [], _ml([0.0, 0.8, 0.2]), ml_only_cap=100)
    assert s["risk_score"].tolist() == [0, 80, 20]


def test_ml_only_is_capped_by_default():
    s = window_scores(_windows(), [], _ml([0.0, 1.0, 0.2]))
    assert s["risk_score"].tolist() == [0, 59, 20]


def test_rule_alert_outranks_ml_only():
    a = FakeAlert("alice", "IAM-001", "2026-11-10T10:10:00Z", "2026-11-10T10:20:00Z", score=70)
    s = window_scores(_windows(), [a], _ml([1.0, 0.0, 0.0]))
    assert s.loc[1, "risk_score"] == 70 and s.loc[0, "risk_score"] == 59


def test_rule_plus_ml_gets_bonus_and_cap():
    a = FakeAlert("alice", "IAM-001", "2026-11-10T10:10:00Z", "2026-11-10T10:20:00Z", score=95)
    s = window_scores(_windows(), [a], _ml([0, 0.9, 0]))
    assert s.loc[1, "risk_score"] == 100


def test_extra_rule_bonus():
    a = FakeAlert("alice", "IAM-001", "2026-11-10T10:10:00Z", "2026-11-10T10:20:00Z")
    b = FakeAlert("alice", "IAM-002", "2026-11-10T10:30:00Z", "2026-11-10T10:40:00Z", score=60)
    s = window_scores(_windows(), [a, b], _ml([0, 0, 0]))
    assert s.loc[1, "risk_score"] == 75


def test_build_alerts_sources_and_ids():
    a = FakeAlert("alice", "IAM-001", "2026-11-10T10:10:00Z", "2026-11-10T10:20:00Z")
    s = window_scores(_windows(), [a], _ml([0.9, 0.6, 0]))
    alerts = build_alerts([a], s)
    sources = {x["rule_id"]: x["detection_source"] for x in alerts}
    assert sources["IAM-001"] == "combined"
    assert sources["ML-IF"] == "ml"
    assert [x["alert_id"] for x in alerts] == ["a-0001", "a-0002"]
    assert {"identity", "score", "event_ids", "first_seen", "last_seen"} <= set(alerts[0])


def test_ml_threshold_controls_ml_only_alerts():
    s = window_scores(_windows(), [], _ml([0.0, 0.6, 0.0]), ml_threshold=70)
    assert build_alerts([], s, ml_threshold=70) == []
    s = window_scores(_windows(), [], _ml([0.0, 0.6, 0.0]), ml_threshold=50)
    assert [a["detection_source"] for a in build_alerts([], s, ml_threshold=50)] == ["ml"]


def test_severity_levels():
    assert [severity(x) for x in (10, 45, 65, 90)] == ["faible", "moyenne", "élevée", "critique"]


def T(hm, day=10):
    return f"2026-11-{day:02d}T{hm}:00Z"


def _alert(i, ident, rule, tech, first, last, score):
    return {
        "alert_id": f"a-{i:04d}", "identity": ident, "detection_source": "rule",
        "rule_id": rule, "mitre_technique": tech, "score": score, "event_ids": [],
        "first_seen": first, "last_seen": last, "description": rule,
    }


def test_correlate_groups_close_alerts_and_splits_far_ones():
    alerts = [
        _alert(1, "alice", "IAM-001", "T1098", T("10:00"), T("10:10"), 70),
        _alert(2, "alice", "LOG-001", "T1562.008", T("12:00"), T("12:05"), 80),
        _alert(3, "alice", "S3-001", "T1530", T("08:00", 12), T("08:05", 12), 50),
        _alert(4, "bob", "AUTH-001", "T1078.004", T("11:00"), T("11:05"), 60),
    ]
    inc = correlate(alerts)
    assert len(inc) == 3
    top = inc[0]
    assert top["identity"] == "alice" and top["n_alerts"] == 2
    assert top["risk_score"] == 85  # 80 + 5 (2 techniques)
    assert top["severity"] == "critique"
    assert top["incident_id"] == "inc-0001"


@dataclass
class FakeEvent:
    identity_name: str
    event_time: str
    event_name: str
    source_ip: str


def test_timeline_is_chronological_and_per_identity():
    events = [
        FakeEvent("alice", "2026-11-10T10:05:00Z", "AttachUserPolicy", "203.0.113.5"),
        FakeEvent("bob", "2026-11-10T10:01:00Z", "ListUsers", "203.0.113.9"),
        FakeEvent("alice", "2026-11-10T09:55:00Z", "CreateUser", "203.0.113.5"),
    ]
    alerts = [_alert(1, "alice", "IAM-001", "T1098", T("10:05"), T("10:06"), 70)]
    tl = timeline("alice", events, alerts)
    assert [e["label"] for e in tl] == ["CreateUser", "IAM-001", "AttachUserPolicy"]
    assert all(e["time"] <= tl[-1]["time"] for e in tl)
