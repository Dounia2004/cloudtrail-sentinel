"""Format d'alerte commun (voir docs/contracts.md) et fonction de construction.

Toutes les règles de détection renvoient des objets `Alert`. Le score donné ici est un
score de base lié à la gravité de la règle ; le module de scoring pourra le recalculer.
"""
from pydantic import BaseModel, Field

from src.ingestion.models import Event

SEVERITY_SCORES = {"low": 20, "medium": 50, "high": 80, "critical": 95}


class Alert(BaseModel):
    """Une alerte de sécurité, au format défini dans docs/contracts.md."""

    alert_id: str
    identity: str
    detection_source: str = "rule"
    rule_id: str
    mitre_technique: str
    score: int = Field(ge=0, le=100)
    event_ids: list[str]
    first_seen: str
    last_seen: str
    description: str


def build_alert(
    rule_id: str,
    mitre_technique: str,
    severity: str,
    events: list[Event],
    description: str,
) -> Alert:
    """Construit une alerte à partir des événements qui l'ont déclenchée."""
    if not events:
        raise ValueError("Une alerte doit s'appuyer sur au moins un événement.")
    ordered = sorted(events, key=lambda e: e.event_time)
    return Alert(
        alert_id=f"{rule_id}:{ordered[0].event_id}",
        identity=ordered[0].identity_name,
        detection_source="rule",
        rule_id=rule_id,
        mitre_technique=mitre_technique,
        score=SEVERITY_SCORES[severity],
        event_ids=[e.event_id for e in ordered],
        first_seen=ordered[0].event_time,
        last_seen=ordered[-1].event_time,
        description=description,
    )
