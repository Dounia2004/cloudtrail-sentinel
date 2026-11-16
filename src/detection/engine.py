"""Moteur de détection : applique toutes les règles aux événements.

Utilisation (depuis la racine du projet, après avoir importé les logs dans SQLite) :
    python -m src.detection.engine
"""
from src.detection.alerts import Alert
from src.detection.rules import RULES
from src.ingestion.models import Event
from src.storage.db import connect, fetch_events


def run_rules(events: list[Event], rules=RULES) -> list[Alert]:
    """Applique chaque règle et renvoie toutes les alertes, triées par date."""
    alerts = []
    for rule in rules:
        alerts.extend(rule.detect(events))
    return sorted(alerts, key=lambda alert: alert.first_seen)


def main() -> None:
    conn = connect()
    events = [Event(**row) for row in fetch_events(conn)]
    conn.close()
    alerts = run_rules(events)
    print(f"{len(events)} événements analysés, {len(alerts)} alertes")
    for alert in alerts:
        print(f"{alert.first_seen}  {alert.rule_id}  {alert.identity}  {alert.description}")


if __name__ == "__main__":
    main()
