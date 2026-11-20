"""Test de bout en bout : logs -> ingestion -> règles -> features -> score -> alertes -> API.

Utilise les fixtures (tests/fixtures) : aucune dépendance au générateur ni au ML, donc rapide
et déterministe. Le ML est couvert par ses propres tests.
"""
import json
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from src.api import replay
from src.api.main import app, get_conn
from src.detection.engine import run_rules
from src.detection.ml.features import build_features
from src.ingestion.models import load_events
from src.scoring.correlation import correlate
from src.scoring.scoring import build_alerts, window_scores
from src.storage.db import connect, init_db, insert_events

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    """Exécute toute la chaîne sur les fixtures et expose l'API sur les résultats."""
    events, rejected = load_events(
        FIXTURES / "cloudtrail_sample.json", FIXTURES / "labels_sample.csv"
    )
    assert events and not rejected

    db_path = str(tmp_path / "e2e.db")
    conn = connect(db_path)
    init_db(conn)
    insert_events(conn, events)
    conn.close()

    rule_alerts = run_rules(events)
    features = build_features(events)
    ml_scores = pd.Series(0.0, index=features.index)  # ML neutre : on teste règles + scoring
    scores = window_scores(features, rule_alerts, ml_scores)
    alerts = build_alerts(rule_alerts, scores)

    out = tmp_path / "output"
    out.mkdir()
    (out / "alerts.json").write_text(json.dumps(alerts), encoding="utf-8")
    monkeypatch.setenv("SENTINEL_OUTPUT_DIR", str(out))

    def override():
        c = connect(db_path)
        try:
            yield c
        finally:
            c.close()

    app.dependency_overrides[get_conn] = override
    yield {"client": TestClient(app), "alerts": alerts, "events": events, "out": out}
    app.dependency_overrides.clear()


def test_alerts_follow_the_contract(pipeline):
    alerts = pipeline["alerts"]
    assert alerts
    keys = {
        "alert_id", "identity", "detection_source", "rule_id", "mitre_technique",
        "score", "event_ids", "first_seen", "last_seen", "description",
    }  # fmt: skip
    for alert in alerts:
        assert keys <= set(alert)
        assert 0 <= alert["score"] <= 100


def test_known_attack_is_detected_and_served(pipeline):
    client = pipeline["client"]
    rules = {a["rule_id"] for a in client.get("/alerts").json()}
    assert "IAM-001" in rules  # attribution de privilèges administrateur
    stats = client.get("/stats").json()
    assert stats["alerts_total"] == len(pipeline["alerts"])
    assert stats["max_score"] >= 80


def test_timeline_mixes_events_and_alerts_in_order(pipeline):
    client = pipeline["client"]
    top = client.get("/alerts").json()[0]
    data = client.get(f"/identities/{top['identity']}/timeline").json()
    kinds = {e["kind"] for e in data["entries"]}
    times = [e["time"] for e in data["entries"]]
    assert kinds == {"event", "alert"}
    assert times == sorted(times)
    assert data["incidents"]


def test_incidents_group_alerts_by_identity(pipeline):
    incidents = correlate(pipeline["alerts"])
    assert incidents
    assert sum(i["n_alerts"] for i in incidents) == len(pipeline["alerts"])


def test_replay_feeds_the_api_progressively(pipeline):
    client, out = pipeline["client"], pipeline["out"]
    seen = []

    def watch(_):
        seen.append(client.get("/stats").json()["alerts_total"])

    replay.run(sleep=watch)
    assert seen[0] == 0
    assert seen == sorted(seen)
    assert client.get("/stats").json()["alerts_total"] == len(pipeline["alerts"])
    assert replay.reset() and not (out / "live_alerts.json").exists()


def test_repeated_requests_work(pipeline):
    # l'API ouvre puis ferme une connexion SQLite par requête
    client = pipeline["client"]
    for _ in range(5):
        assert client.get("/events", params={"limit": 1}).status_code == 200
