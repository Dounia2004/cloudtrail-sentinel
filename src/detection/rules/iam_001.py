"""IAM-001 : droits administrateur attribués (MITRE T1098, Account Manipulation).

Condition : un appel réussi à AttachUserPolicy, AttachRolePolicy ou AttachGroupPolicy
avec la politique gérée AWS « AdministratorAccess » (toutes les actions sur toutes les
ressources). Faux positif probable : un administrateur qui configure légitimement un compte.

Limites : une politique personnalisée équivalente à l'administrateur n'est pas détectée,
et un appel refusé (errorCode présent) ne déclenche pas d'alerte.
"""
import json

from src.detection.alerts import Alert, build_alert
from src.ingestion.models import Event

RULE_ID = "IAM-001"
MITRE = "T1098"
SEVERITY = "high"

ATTACH_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
TARGET_KEYS = ("userName", "roleName", "groupName")


def _params(event: Event) -> dict:
    """Lit request_params (texte JSON) ; renvoie {} si absent ou invalide."""
    if not event.request_params:
        return {}
    try:
        data = json.loads(event.request_params)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def detect(events: list[Event]) -> list[Alert]:
    """Renvoie une alerte par attribution de droits administrateur."""
    alerts = []
    for event in events:
        if event.event_name not in ATTACH_EVENTS or event.error_code:
            continue
        params = _params(event)
        if params.get("policyArn") != ADMIN_POLICY_ARN:
            continue
        target = next((params[key] for key in TARGET_KEYS if key in params), "inconnu")
        description = (
            f"{event.identity_name} a attribué AdministratorAccess à {target} "
            f"({event.event_name})"
        )
        alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, [event], description))
    return alerts
