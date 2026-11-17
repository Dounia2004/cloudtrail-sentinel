"""AUTH-002 : échecs de connexion puis succès (MITRE T1110, Brute Force).

Condition : au moins 5 échecs de ConsoleLogin pour une même identité en 10 minutes, suivis
d'une connexion réussie dans les 10 minutes qui suivent le dernier échec. Un mot de passe
a probablement été deviné. Faux positif probable : un utilisateur qui oublie son mot de passe.

Limite : des échecs répétés sans succès ne déclenchent pas cette règle.
"""
from datetime import timedelta

from src.detection.alerts import Alert, build_alert
from src.detection.rules.common import (
    duration_seconds,
    find_bursts,
    group_by_identity,
    parse_time,
)
from src.ingestion.models import Event

RULE_ID = "AUTH-002"
MITRE = "T1110"
SEVERITY = "high"

THRESHOLD = 5
WINDOW = timedelta(minutes=10)


def detect(
    events: list[Event], threshold: int = THRESHOLD, window: timedelta = WINDOW
) -> list[Alert]:
    """Renvoie une alerte par série d'échecs suivie d'un succès."""
    logins = [event for event in events if event.event_name == "ConsoleLogin"]
    alerts = []
    for identity_events in group_by_identity(logins).values():
        failures = [e for e in identity_events if e.login_result == "Failure"]
        successes = [e for e in identity_events if e.login_result == "Success"]
        for burst in find_bursts(failures, window, threshold):
            last_failure = parse_time(burst[-1].event_time)
            success = next(
                (
                    s
                    for s in successes
                    if last_failure < parse_time(s.event_time) <= last_failure + window
                ),
                None,
            )
            if success is None:
                continue
            involved = burst + [success]
            description = (
                f"{success.identity_name} : {len(burst)} échecs de connexion puis un succès "
                f"(durée totale {duration_seconds(involved)} s)"
            )
            alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, involved, description))
    return alerts
