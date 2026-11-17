"""IAM-006 : rafale de reconnaissance IAM (MITRE T1087.004, Cloud Account Discovery).

Condition : une même identité enchaîne au moins 5 appels IAM de lecture (List*, Get*) en
5 minutes, avec au moins 4 types d'appels différents. Un attaquant explore le compte
(utilisateurs, rôles, politiques) avant d'agir. Faux positif probable : un outil d'audit.

Limites : un seul type d'appel répété (par exemple un script qui interroge ListUsers) n'est
pas signalé, et les appels refusés sont ignorés.
"""
from datetime import timedelta

from src.detection.alerts import Alert, build_alert
from src.detection.rules.common import duration_seconds, find_bursts, group_by_identity
from src.ingestion.models import Event

RULE_ID = "IAM-006"
MITRE = "T1087.004"
SEVERITY = "medium"

IAM_SOURCE = "iam.amazonaws.com"
THRESHOLD = 5
WINDOW = timedelta(minutes=5)
MIN_DISTINCT = 4


def _is_recon(event: Event) -> bool:
    return (
        event.event_source == IAM_SOURCE
        and event.event_name.startswith(("List", "Get"))
        and not event.error_code
    )


def detect(
    events: list[Event],
    threshold: int = THRESHOLD,
    window: timedelta = WINDOW,
    min_distinct: int = MIN_DISTINCT,
) -> list[Alert]:
    """Renvoie une alerte par rafale de reconnaissance IAM."""
    candidates = [event for event in events if _is_recon(event)]
    alerts = []
    for identity_events in group_by_identity(candidates).values():
        for burst in find_bursts(identity_events, window, threshold):
            names = {event.event_name for event in burst}
            if len(names) < min_distinct:
                continue
            description = (
                f"{burst[0].identity_name} a enchaîné {len(burst)} appels IAM de lecture "
                f"({len(names)} types) en {duration_seconds(burst)} s"
            )
            alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, burst, description))
    return alerts
