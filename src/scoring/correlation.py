"""Corrélation des alertes par identité (incidents) et chronologie d'une identité."""
from __future__ import annotations

import pandas as pd

INCIDENT_GAP = "6h"  # deux alertes séparées de plus que ça = deux incidents distincts
TECHNIQUE_BONUS = 5
TECHNIQUE_CAP = 15


def _severity(score: float) -> str:
    if score >= 80:
        return "critique"
    if score >= 60:
        return "élevée"
    if score >= 40:
        return "moyenne"
    return "faible"


def _ts(value: object) -> pd.Timestamp:
    return pd.to_datetime(value, utc=True)


def _incident(identity: str, group: list[dict]) -> dict:
    techniques = sorted({a["mitre_technique"] for a in group if a["mitre_technique"]})
    top = max(a["score"] for a in group)
    bonus = min(TECHNIQUE_BONUS * max(len(techniques) - 1, 0), TECHNIQUE_CAP)
    risk = int(min(top + bonus, 100))
    return {
        "identity": identity,
        "first_seen": min(group, key=lambda a: _ts(a["first_seen"]))["first_seen"],
        "last_seen": max(group, key=lambda a: _ts(a["last_seen"]))["last_seen"],
        "n_alerts": len(group),
        "alert_ids": [a["alert_id"] for a in group],
        "rules": sorted({a["rule_id"] for a in group}),
        "techniques": techniques,
        "max_score": top,
        "risk_score": risk,
        "severity": _severity(risk),
    }


def correlate(alerts: list[dict], gap: str = INCIDENT_GAP) -> list[dict]:
    """Regroupe les alertes d'une même identité proches dans le temps en incidents."""
    by_identity: dict[str, list[dict]] = {}
    for alert in alerts:
        by_identity.setdefault(alert["identity"], []).append(alert)

    incidents: list[dict] = []
    for identity, items in by_identity.items():
        items = sorted(items, key=lambda a: _ts(a["first_seen"]))
        group = [items[0]]
        group_end = _ts(items[0]["last_seen"])
        for alert in items[1:]:
            if _ts(alert["first_seen"]) <= group_end + pd.Timedelta(gap):
                group.append(alert)
                group_end = max(group_end, _ts(alert["last_seen"]))
            else:
                incidents.append(_incident(identity, group))
                group, group_end = [alert], _ts(alert["last_seen"])
        incidents.append(_incident(identity, group))

    incidents.sort(key=lambda i: (-i["risk_score"], _ts(i["first_seen"])))
    for n, incident in enumerate(incidents, start=1):
        incident["incident_id"] = f"inc-{n:04d}"
    return [{"incident_id": i.pop("incident_id"), **i} for i in incidents]


def _attr(obj: object, *names: str) -> object:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


def timeline(identity: str, events: list, alerts: list[dict]) -> list[dict]:
    """Chronologie d'une identité : événements et alertes, du plus ancien au plus récent."""
    entries: list[dict] = []
    for event in events:
        if _attr(event, "identity_name", "identity") != identity:
            continue
        entries.append(
            {
                "time": _ts(_attr(event, "event_time")).isoformat(),
                "kind": "event",
                "label": str(_attr(event, "event_name")),
                "detail": str(_attr(event, "source_ip") or ""),
            }
        )
    for alert in alerts:
        if alert["identity"] != identity:
            continue
        entries.append(
            {
                "time": _ts(alert["first_seen"]).isoformat(),
                "kind": "alert",
                "label": alert["rule_id"],
                "detail": alert["description"],
                "score": alert["score"],
            }
        )
    return sorted(entries, key=lambda e: (e["time"], e["kind"] != "alert"))
