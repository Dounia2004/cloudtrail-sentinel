import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from src.api.main import app, get_conn
from src.storage.db import COLUMNS, connect, init_db


def _alert(i, identity, rule, score, first, source="rule", tech="T1098"):
    return {
        "alert_id": f"a-{i:04d}",
        "identity": identity,
        "detection_source": source,
        "rule_id": rule,
        "mitre_technique": tech,
        "score": score,
        "event_ids": [],
        "first_seen": first,
        "last_seen": first,
        "description": f"alerte {rule}",
    }


ALERTS = [
    _alert(1, "alice", "IAM-001", 90, "2026-11-10T10:05:00Z"),
    _alert(2, "alice", "LOG-001", 70, "2026-11-10T10:30:00Z", tech="T1562.008"),
    _alert(3, "bob", "ML-IF", 30, "2026-11-10T12:00:00Z", source="ml", tech=""),
]


def _row(event_id, when, identity, name):
    values = dict.fromkeys(COLUMNS)
    values.update(
        event_id=event_id,
        event_time=when,
        event_source="iam.amazonaws.com",
        event_name=name,
        identity_name=identity,
        source_ip="203.0.113.5",
        scenario="normal",
        is_attack=0,
    )
    return values


@pytest.fixture
def client(tmp_path, monkeypatch):
    out = tmp_path / "output"
    out.mkdir()
    (out / "alerts.json").write_text(json.dumps(ALERTS), encoding="utf-8")
    monkeypatch.setenv("SENTINEL_OUTPUT_DIR", str(out))

    db_path = str(tmp_path / "test.db")
    conn = connect(db_path)
    init_db(conn)
    rows = [
        _row("e-1", "2026-11-10T09:55:00Z", "alice", "CreateUser"),
        _row("e-2", "2026-11-10T10:05:00Z", "alice", "AttachUserPolicy"),
        _row("e-3", "2026-11-10T11:00:00Z", "bob", "ListUsers"),
    ]
    marks = ",".join("?" for _ in COLUMNS)
    conn.executemany(
        f"INSERT INTO events ({','.join(COLUMNS)}) VALUES ({marks})",
        [tuple(r[c] for c in COLUMNS) for r in rows],
    )
    conn.commit()
    conn.close()

    def override() -> sqlite3.Connection:
        c = connect(db_path)
        try:
            yield c
        finally:
            c.close()

    app.dependency_overrides[get_conn] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_alerts_sorted_by_score_with_severity(client):
    data = client.get("/alerts").json()
    assert [a["alert_id"] for a in data] == ["a-0001", "a-0002", "a-0003"]
    assert data[0]["severity"] == "critique"


def test_alerts_filters(client):
    assert len(client.get("/alerts", params={"min_score": 50}).json()) == 2
    assert len(client.get("/alerts", params={"identity": "bob"}).json()) == 1
    assert len(client.get("/alerts", params={"source": "ml"}).json()) == 1


def test_alert_detail_and_404(client):
    assert client.get("/alerts/a-0002").json()["rule_id"] == "LOG-001"
    assert client.get("/alerts/a-9999").status_code == 404


def test_stats(client):
    s = client.get("/stats").json()
    assert s["alerts_total"] == 3
    assert s["alerts_active"] == 2
    assert s["max_score"] == 90
    assert s["identities_affected"] == 1
    assert s["by_source"] == {"rule": 2, "ml": 1}


def test_events_filters_and_limit(client):
    assert len(client.get("/events").json()) == 3
    assert len(client.get("/events", params={"identity": "alice"}).json()) == 2
    assert len(client.get("/events", params={"limit": 1}).json()) == 1
    listed = client.get("/events", params={"event_name": "ListUsers"}).json()
    assert listed[0]["identity_name"] == "bob"
    after = client.get("/events", params={"from": "2026-11-10T10:00:00Z"}).json()
    assert {e["event_id"] for e in after} == {"e-2", "e-3"}


def test_timeline_is_chronological_with_alerts_and_incident(client):
    data = client.get("/identities/alice/timeline").json()
    labels = [e["label"] for e in data["entries"]]
    assert labels == ["CreateUser", "IAM-001", "AttachUserPolicy", "LOG-001"]
    assert data["incidents"][0]["n_alerts"] == 2


def test_timeline_unknown_identity_404(client):
    assert client.get("/identities/nobody/timeline").status_code == 404


def test_incidents_route(client):
    incidents = client.get("/incidents", params={"identity": "alice"}).json()
    assert len(incidents) == 1 and incidents[0]["severity"] == "critique"


def test_live_file_takes_priority(client, tmp_path):
    live = tmp_path / "output" / "live_alerts.json"
    live.write_text(json.dumps(ALERTS[:1]), encoding="utf-8")
    assert client.get("/stats").json()["alerts_total"] == 1
