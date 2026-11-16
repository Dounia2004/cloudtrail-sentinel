"""IAM-001 : droits administrateur attribués (MITRE T1098, Account Manipulation).

Condition : un appel réussi à AttachUserPolicy, AttachRolePolicy ou AttachGroupPolicy
avec la politique gérée AWS « AdministratorAccess » (toutes les actions sur toutes les
ressources). Faux positif probable : un administrateur qui configure légitimement un compte.

Limites : une politique personnalisée équivalente à l'administrateur n'est pas détectée,
et un appel refusé (errorCode présent) ne déclenche pas d'alerte.
"""
from src.detection.alerts import Alert, build_alert
from src.detection.rules.common import first_value, request_params, successful_events
from src.ingestion.models import Event

RULE_ID = "IAM-001"
MITRE = "T1098"
SEVERITY = "high"

ATTACH_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
TARGET_KEYS = ("userName", "roleName", "groupName")


def detect(events: list[Event]) -> list[Alert]:
    """Renvoie une alerte par attribution de droits administrateur."""
    alerts = []
    for event in successful_events(events, ATTACH_EVENTS):
        params = request_params(event)
        if params.get("policyArn") != ADMIN_POLICY_ARN:
            continue
        target = first_value(params, TARGET_KEYS)
        description = (
            f"{event.identity_name} a attribué AdministratorAccess à {target} "
            f"({event.event_name})"
        )
        alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, [event], description))
    return alerts
