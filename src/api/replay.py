"""Rejeu d'un scénario avec délai simulé (démonstration quasi temps réel).

Les alertes de `alerts.json` sont republiées une par une dans `live_alerts.json`, dans
l'ordre chronologique. L'écart réel entre deux alertes est compressé : avec --speed 3600,
une heure simulée dure une seconde. L'API et le dashboard lisent ce fichier en priorité.

Utilisation :
    python -m src.api.replay                  # rejoue tout
    python -m src.api.replay --identity alice # rejoue une seule identité
    python -m src.api.replay --reset          # supprime le rejeu, retour aux données complètes
"""
from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable

import pandas as pd

from src.api.store import ALERTS_FILE, LIVE_FILE, output_dir


def plan_delays(alerts: list[dict], speed: float, max_delay: float) -> list[float]:
    """Délai (en secondes réelles) à attendre avant chaque alerte."""
    delays, previous = [], None
    for alert in alerts:
        start = pd.to_datetime(alert["first_seen"], utc=True)
        gap = 0.0 if previous is None else max((start - previous).total_seconds(), 0.0)
        delays.append(min(gap / speed, max_delay))
        previous = start
    return delays


def _write(items: list[dict]) -> None:
    path = output_dir() / LIVE_FILE
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def reset() -> bool:
    path = output_dir() / LIVE_FILE
    if path.exists():
        path.unlink()
        return True
    return False


def run(
    speed: float = 3600.0,
    max_delay: float = 3.0,
    identity: str | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    source = output_dir() / ALERTS_FILE
    alerts = json.loads(source.read_text(encoding="utf-8")) if source.exists() else []
    if identity:
        alerts = [a for a in alerts if a["identity"] == identity]
    alerts.sort(key=lambda a: pd.to_datetime(a["first_seen"], utc=True))

    output_dir().mkdir(parents=True, exist_ok=True)
    published: list[dict] = []
    _write(published)
    for alert, delay in zip(alerts, plan_delays(alerts, speed, max_delay), strict=True):
        sleep(delay)
        published.append(alert)
        _write(published)
        print(f"[{len(published)}/{len(alerts)}] {alert['alert_id']} {alert['identity']} "
              f"{alert['rule_id']} score={alert['score']}")
    return len(published)


def main() -> None:
    ap = argparse.ArgumentParser(description="Rejoue les alertes avec un délai simulé.")
    ap.add_argument("--speed", type=float, default=3600.0, help="1 h simulée = 3600/speed s")
    ap.add_argument("--max-delay", type=float, default=3.0, help="attente maximale (s)")
    ap.add_argument("--identity", default=None)
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()
    if args.reset:
        print("rejeu supprimé" if reset() else "aucun rejeu en cours")
        return
    n = run(args.speed, args.max_delay, args.identity)
    print(f"{n} alertes rejouées. Utilisez --reset pour revenir aux données complètes.")


if __name__ == "__main__":
    main()
