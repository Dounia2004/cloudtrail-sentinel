"""API REST de CloudTrail Sentinel (routes du contrat `docs/contracts.md`).

Lancement (depuis la racine du projet) :
    uvicorn src.api.main:app --reload
Documentation interactive : http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import sqlite3
from collections import Counter
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query

from src.api.store import load_alerts, load_incidents
from src.scoring.correlation import timeline as build_timeline
from src.storage.db import connect, fetch_events

ACTIVE_MIN_SCORE = 40  # une alerte est « active » à partir de ce score

app = FastAPI(title="CloudTrail Sentinel API", version="0.6.0")


def get_conn() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]


def _severity(score: float) -> str:
    if score >= 80:
        return "critique"
    if score >= 60:
        return "élevée"
    if score >= 40:
        return "moyenne"
    return "faible"


def _with_severity(alert: dict) -> dict:
    return {**alert, "severity": _severity(alert["score"])}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/events")
def events(
    conn: Conn,
    identity: str | None = None,
    event_name: str | None = None,
    from_: Annotated[str | None, Query(alias="from")] = None,
    to: str | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
) -> list[dict]:
    rows = fetch_events(conn, identity=identity, event_name=event_name, start=from_, end=to)
    return rows[:limit]


@app.get("/alerts")
def alerts(
    min_score: Annotated[int, Query(ge=0, le=100)] = 0,
    identity: str | None = None,
    source: str | None = None,
) -> list[dict]:
    items = [
        _with_severity(a)
        for a in load_alerts()
        if a["score"] >= min_score
        and (identity is None or a["identity"] == identity)
        and (source is None or a["detection_source"] == source)
    ]
    return sorted(items, key=lambda a: (-a["score"], a["first_seen"]))


@app.get("/alerts/{alert_id}")
def alert_detail(alert_id: str) -> dict:
    for alert in load_alerts():
        if alert["alert_id"] == alert_id:
            return _with_severity(alert)
    raise HTTPException(status_code=404, detail=f"Alerte {alert_id} introuvable")


@app.get("/incidents")
def incidents(identity: str | None = None) -> list[dict]:
    items = load_incidents()
    return [i for i in items if identity is None or i["identity"] == identity]


@app.get("/identities/{name}/timeline")
def identity_timeline(name: str, conn: Conn) -> dict:
    rows = fetch_events(conn, identity=name)
    identity_alerts = [a for a in load_alerts() if a["identity"] == name]
    if not rows and not identity_alerts:
        raise HTTPException(status_code=404, detail=f"Identité {name} inconnue")
    return {
        "identity": name,
        "incidents": [i for i in load_incidents() if i["identity"] == name],
        "entries": build_timeline(name, rows, identity_alerts),
    }


@app.get("/stats")
def stats() -> dict:
    items = load_alerts()
    active = [a for a in items if a["score"] >= ACTIVE_MIN_SCORE]
    return {
        "alerts_total": len(items),
        "alerts_active": len(active),
        "max_score": max((a["score"] for a in items), default=0),
        "identities_affected": len({a["identity"] for a in active}),
        "incidents": len(load_incidents()),
        "by_source": dict(Counter(a["detection_source"] for a in items)),
        "by_severity": dict(Counter(_severity(a["score"]) for a in items)),
        "by_rule": dict(Counter(a["rule_id"] for a in items)),
    }
