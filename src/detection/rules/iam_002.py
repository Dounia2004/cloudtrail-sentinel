"""IAM-002 : nouvelle version de politique définie par défaut (MITRE T1098).

Condition : un appel réussi à CreatePolicyVersion avec setAsDefault à vrai. Un attaquant peut
ainsi remplacer le contenu d'une politique existante par une version qui donne tous les droits.
Faux positif probable : une mise à jour normale d'une politique par un administrateur.

Limite : le contenu de la politique (policyDocument) n'est pas analysé.
"""
from src.detection.alerts import Alert, build_alert
from src.detection.rules.common import request_params, successful_events
from src.ingestion.models import Event

RULE_ID = "IAM-002"
MITRE = "T1098"
SEVERITY = "high"


def detect(events: list[Event]) -> list[Alert]:
    """Renvoie une alerte par nouvelle version de politique activée."""
    alerts = []
    for event in successful_events(events, {"CreatePolicyVersion"}):
        params = request_params(event)
        if str(params.get("setAsDefault", "")).lower() != "true":
            continue
        policy = params.get("policyArn", "inconnue")
        description = (
            f"{event.identity_name} a défini une nouvelle version par défaut "
            f"de la politique {policy}"
        )
        alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, [event], description))
    return alerts
