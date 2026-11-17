"""AUTH-004 : usage du compte root (MITRE T1078.004).

Condition : tout événement dont l'identité est de type Root, qu'il ait réussi ou non. Le compte
root a tous les droits et ne devrait presque jamais servir. Faux positif probable : une
opération rare qui exige légitimement le compte root.

Limite : une alerte par événement ; une session root longue produit donc plusieurs alertes
(la corrélation par identité les regroupera plus tard).
"""
from src.detection.alerts import Alert, build_alert
from src.ingestion.models import Event

RULE_ID = "AUTH-004"
MITRE = "T1078.004"
SEVERITY = "high"


def detect(events: list[Event]) -> list[Alert]:
    """Renvoie une alerte par événement effectué avec le compte root."""
    alerts = []
    for event in events:
        if event.identity_type != "Root":
            continue
        description = (
            f"Le compte root a exécuté {event.event_name} depuis {event.source_ip}"
        )
        alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, [event], description))
    return alerts
