"""LOG-001 : journalisation CloudTrail coupée ou modifiée (MITRE T1562.008).

Condition : un appel réussi à StopLogging, DeleteTrail ou UpdateTrail. Sans journalisation,
plus aucune détection n'est possible : c'est une règle de gravité critique. Faux positif
probable : une opération de maintenance planifiée.

Limite : une tentative refusée (errorCode présent) ne déclenche pas d'alerte.
"""
from src.detection.alerts import Alert, build_alert
from src.detection.rules.common import request_params, successful_events
from src.ingestion.models import Event

RULE_ID = "LOG-001"
MITRE = "T1562.008"
SEVERITY = "critical"

LOGGING_EVENTS = {"StopLogging", "DeleteTrail", "UpdateTrail"}


def detect(events: list[Event]) -> list[Alert]:
    """Renvoie une alerte par action qui coupe ou modifie la journalisation."""
    alerts = []
    for event in successful_events(events, LOGGING_EVENTS):
        trail = request_params(event).get("name", "inconnue")
        description = f"{event.identity_name} a exécuté {event.event_name} sur la trace {trail}"
        alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, [event], description))
    return alerts
