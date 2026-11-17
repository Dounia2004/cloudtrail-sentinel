"""AUTH-001 : connexion à la console sans MFA (MITRE T1078.004, Valid Accounts: Cloud Accounts).

Condition : un ConsoleLogin réussi où l'authentification multifacteur (MFA) n'a pas été utilisée.
Sans second facteur, un mot de passe volé suffit pour entrer. Faux positif probable : un compte
de service ou un compte qui n'a pas encore activé le MFA.

Limite : seules les connexions réussies sont examinées (les échecs sont vus par AUTH-002).
"""
from src.detection.alerts import Alert, build_alert
from src.ingestion.models import Event

RULE_ID = "AUTH-001"
MITRE = "T1078.004"
SEVERITY = "medium"


def detect(events: list[Event]) -> list[Alert]:
    """Renvoie une alerte par connexion réussie sans MFA."""
    alerts = []
    for event in events:
        if event.event_name != "ConsoleLogin" or event.login_result != "Success":
            continue
        if event.mfa_used != 0:
            continue
        description = (
            f"{event.identity_name} s'est connecté à la console sans MFA "
            f"depuis {event.source_ip}"
        )
        alerts.append(build_alert(RULE_ID, MITRE, SEVERITY, [event], description))
    return alerts
