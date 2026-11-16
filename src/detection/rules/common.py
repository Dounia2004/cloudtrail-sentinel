"""Fonctions partagées par les règles de détection."""
import json
from collections.abc import Iterable, Iterator

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
