"""S3-001 : lectures S3 en masse (MITRE T1530, Data from Cloud Storage).

Condition : au moins 10 lectures S3 (GetObject, ListBucket, ListObjects, ListObjectsV2) par
une même identité en 10 minutes. Un attaquant télécharge des données. Faux positif probable :
une sauvegarde ou une migration de données.

Limites : la taille des données et la sensibilité du bucket ne sont pas prises en compte.
"""
from datetime import timedelta

from src.detection.alerts import Alert, build_alert
from src.detection.rules.common import (
    duration_seconds,
    find_bursts,
    group_by_identity,
    successful_events,
)
from src.ingestion.models import Event

RULE_ID = "S3-001"
MITRE = "T1530"
SEVERITY = "high"

READ_EVENTS = {"GetObject", "ListBucket", "ListObjects", "ListObjectsV2"}
THRESHOLD = 10
WINDOW = timedelta(minutes=10)


def detect(
    events: list[Event], threshold: int = THRESHOLD, window: timedelta = WINDOW
) -> list[Alert]:
    """Renvoie une alerte par rafale de lectures S3."""
    candidates = list(successful_events(events, READ_EVENTS))
    alerts = []
    for identity_events in group_by_identity(candidates).values():
        for burst in find_bursts(identity_events, window, threshold):
            description = (
                f"{burst[0].identity_name} a effectué {len(burst)} lectures S3 "
                f"en {duration_seconds(burst)} s"
            )
            alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, burst, description))
    return alerts
