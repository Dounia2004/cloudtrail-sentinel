"""AUTH-003 : adresse IP jamais vue pour cette identité (MITRE T1078.004).

Condition : un événement dont l'adresse IP n'a jamais été utilisée auparavant par la même
identité, alors que cette identité a déjà au moins 5 événements d'historique. Une seule alerte
est émise par nouvelle adresse (les événements suivants depuis la même IP sont ignorés).
Faux positif probable : télétravail, voyage, VPN, changement de réseau.

Limites : l'historique est celui des événements analysés (pas de base de référence longue),
une identité sans historique suffisant n'est pas évaluée, et l'IP n'est pas géolocalisée.
"""
from src.detection.alerts import Alert, build_alert
from src.detection.rules.common import group_by_identity
from src.ingestion.models import Event

RULE_ID = "AUTH-003"
MITRE = "T1078.004"
SEVERITY = "medium"

MIN_HISTORY = 5
SERVICE_SUFFIX = ".amazonaws.com"  # appels faits par un service AWS : pas une vraie IP


def detect(events: list[Event], min_history: int = MIN_HISTORY) -> list[Alert]:
    """Renvoie une alerte à la première apparition de chaque nouvelle IP d'une identité."""
    alerts = []
    for identity_events in group_by_identity(events).values():
        seen_ips: set[str] = set()
        for history_size, event in enumerate(identity_events):
            ip = event.source_ip
            if ip.endswith(SERVICE_SUFFIX) or ip in seen_ips:
                continue
            if history_size >= min_history:
                description = (
                    f"{event.identity_name} a agi depuis une IP jamais vue pour cette "
                    f"identité : {ip} ({event.event_name})"
                )
                alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, [event], description))
            seen_ips.add(ip)
    return alerts
