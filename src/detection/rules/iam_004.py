"""IAM-004 : clé d'accès créée pour un autre compte (MITRE T1098.001).

Condition : un appel réussi à CreateAccessKey où l'utilisateur ciblé (userName) est différent
de l'identité qui fait l'appel. Un attaquant s'offre ainsi un accès permanent à un autre compte.
Faux positif probable : un administrateur qui dépanne un collègue.

Limite : sans userName dans la requête, la clé est créée pour soi-même : pas d'alerte.
"""
from src.detection.alerts import Alert, build_alert
from src.detection.rules.common import request_params, successful_events
from src.ingestion.models import Event

RULE_ID = "IAM-004"
MITRE = "T1098.001"
SEVERITY = "high"


def detect(events: list[Event]) -> list[Alert]:
    """Renvoie une alerte par clé d'accès créée pour un autre utilisateur."""
    alerts = []
    for event in successful_events(events, {"CreateAccessKey"}):
        target = request_params(event).get("userName")
        if not target or target == event.identity_name:
            continue
        description = f"{event.identity_name} a créé une clé d'accès pour {target}"
        alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, [event], description))
    return alerts
