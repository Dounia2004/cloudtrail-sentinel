"""Lecture des alertes produites par `python -m src.scoring.scoring` (fichiers JSON).

Pendant un rejeu (src.api.replay), le fichier `live_alerts.json` est prioritaire : l'API et
le dashboard voient alors les alertes arriver une par une.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from src.scoring.correlation import correlate

ALERTS_FILE = "alerts.json"
LIVE_FILE = "live_alerts.json"


def output_dir() -> Path:
    return Path(os.environ.get("SENTINEL_OUTPUT_DIR", "data/output"))


def _read(name: str) -> list[dict]:
    path = output_dir() / name
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def load_alerts() -> list[dict]:
    live = output_dir() / LIVE_FILE
    return _read(LIVE_FILE if live.exists() else ALERTS_FILE)


def load_incidents() -> list[dict]:
    return correlate(load_alerts())
