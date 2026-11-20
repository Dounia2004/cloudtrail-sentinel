import json

import pytest

from src.api.replay import plan_delays, reset, run


def _alert(i, identity, first):
    return {
        "alert_id": f"a-{i:04d}",
        "identity": identity,
        "detection_source": "rule",
        "rule_id": "IAM-001",
        "mitre_technique": "T1098",
        "score": 80,
        "event_ids": [],
        "first_seen": first,
        "last_seen": first,
        "description": "x",
    }


ALERTS = [
    _alert(1, "alice", "2026-11-10T10:00:00Z"),
    _alert(2, "alice", "2026-11-10T11:00:00Z"),
    _alert(3, "bob", "2026-11-12T09:00:00Z"),
]


@pytest.fixture
def out(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_OUTPUT_DIR", str(tmp_path))
    (tmp_path / "alerts.json").write_text(json.dumps(ALERTS), encoding="utf-8")
    return tmp_path


def test_plan_delays_compresses_and_caps():
    assert plan_delays(ALERTS, speed=3600, max_delay=3) == [0.0, 1.0, 3.0]


def test_run_publishes_progressively(out):
    sizes = []

    def fake_sleep(_):
        sizes.append(len(json.loads((out / "live_alerts.json").read_text(encoding="utf-8"))))

    assert run(sleep=fake_sleep) == 3
    assert sizes == [0, 1, 2]
    assert len(json.loads((out / "live_alerts.json").read_text(encoding="utf-8"))) == 3


def test_run_filters_identity(out):
    assert run(identity="bob", sleep=lambda _: None) == 1


def test_reset_removes_live_file(out):
    run(sleep=lambda _: None)
    assert reset() is True
    assert not (out / "live_alerts.json").exists()
    assert reset() is False
