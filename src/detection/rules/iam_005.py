"""IAM-005 : nouvel utilisateur ou mot de passe de connexion créé (MITRE T1136.003).

Condition : un appel réussi à CreateUser ou CreateLoginProfile. Un attaquant crée un compte
(ou un mot de passe pour un compte existant) pour garder un accès. Faux positif probable :
l'arrivée d'un nouvel employé.
"""
from src.detection.alerts import Alert, build_alert
from src.detection.rules.common import request_params, successful_events
from src.ingestion.models import Event

RULE_ID = "IAM-005"
MITRE = "T1136.003"
SEVERITY = "medium"

ACTIONS = {
    "CreateUser": "a créé l'utilisateur",
    "CreateLoginProfile": "a créé un mot de passe de connexion pour",
}


def detect(events: list[Event]) -> list[Alert]:
    """Renvoie une alerte par création d'utilisateur ou de profil de connexion."""
    alerts = []
    for event in successful_events(events, set(ACTIONS)):
        target = request_params(event).get("userName", "inconnu")
        description = f"{event.identity_name} {ACTIONS[event.event_name]} {target}"
        alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, [event], description))
    return alerts
