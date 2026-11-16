"""IAM-003 : politique en ligne ajoutée (MITRE T1098).

Condition : un appel réussi à PutUserPolicy, PutRolePolicy ou PutGroupPolicy. Une politique
« en ligne » est attachée directement à une identité, ce qui est moins visible qu'une
politique gérée. Faux positif probable : un outil d'automatisation d'infrastructure.
"""
from src.detection.alerts import Alert, build_alert
from src.detection.rules.common import first_value, request_params, successful_events
from src.ingestion.models import Event

RULE_ID = "IAM-003"
MITRE = "T1098"
SEVERITY = "medium"

PUT_EVENTS = {"PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"}
TARGET_KEYS = ("userName", "roleName", "groupName")


def detect(events: list[Event]) -> list[Alert]:
    """Renvoie une alerte par politique en ligne ajoutée."""
    alerts = []
    for event in successful_events(events, PUT_EVENTS):
        params = request_params(event)
        target = first_value(params, TARGET_KEYS)
        policy_name = params.get("policyName", "inconnue")
        description = (
            f"{event.identity_name} a ajouté la politique en ligne {policy_name} "
            f"à {target} ({event.event_name})"
        )
        alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, [event], description))
    return alerts
