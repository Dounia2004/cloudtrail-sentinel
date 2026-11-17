"""Fonctions partagées par les règles de détection."""
import json
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta

from src.ingestion.models import Event


def request_params(event: Event) -> dict:
    """Lit request_params (texte JSON) ; renvoie {} si absent ou invalide."""
    if not event.request_params:
        return {}
    try:
        data = json.loads(event.request_params)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def successful_events(events: Iterable[Event], names: set[str]) -> Iterator[Event]:
    """Événements dont le nom est dans `names` et dont l'appel a réussi (pas d'errorCode)."""
    for event in events:
        if event.event_name in names and not event.error_code:
            yield event


def first_value(params: dict, keys: Iterable[str], default: str = "inconnu"):
    """Première valeur trouvée dans `params` parmi `keys` (sinon `default`)."""
    return next((params[key] for key in keys if key in params), default)


def parse_time(value: str) -> datetime:
    """Convertit une date ISO 8601 UTC (ex. 2026-11-10T10:25:00Z) en datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def group_by_identity(events: Iterable[Event]) -> dict[str, list[Event]]:
    """Regroupe les événements par identité, chaque liste étant triée par date."""
    groups: dict[str, list[Event]] = {}
    for event in events:
        groups.setdefault(event.identity_name, []).append(event)
    for group in groups.values():
        group.sort(key=lambda e: e.event_time)
    return groups


def find_bursts(events: list[Event], window: timedelta, threshold: int) -> list[list[Event]]:
    """Trouve les rafales : au moins `threshold` événements dans une fenêtre de `window`.

    Les événements doivent être triés par date (voir group_by_identity). Chaque rafale part
    d'un événement et regroupe tous ceux qui suivent dans la fenêtre. Les rafales ne se
    chevauchent pas : après une rafale, on repart de l'événement suivant.
    """
    bursts = []
    i = 0
    while i < len(events):
        start = parse_time(events[i].event_time)
        j = i
        while j + 1 < len(events) and parse_time(events[j + 1].event_time) - start <= window:
            j += 1
        if j - i + 1 >= threshold:
            bursts.append(events[i : j + 1])
            i = j + 1
        else:
            i += 1
    return bursts


def duration_seconds(events: list[Event]) -> int:
    """Durée en secondes entre le premier et le dernier événement (triés par date)."""
    delta = parse_time(events[-1].event_time) - parse_time(events[0].event_time)
    return int(delta.total_seconds())
