from pathlib import Path

import pytest

from src.ingestion.models import Event, load_events

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixture_events():
    """Les événements des fixtures (logs étiquetés, voir tests/fixtures/)."""
    events, _ = load_events(
        FIXTURES / "cloudtrail_sample.json", FIXTURES / "labels_sample.csv"
    )
    return events


@pytest.fixture
def make_event():
    """Fabrique un Event de test ; les champs sont modifiables avec des arguments."""

    def _make(**overrides):
        data = {
            "event_id": "e-1",
            "event_time": "2026-11-10T10:25:00Z",
            "event_source": "iam.amazonaws.com",
            "event_name": "CreateUser",
            "aws_region": "us-east-1",
            "identity_type": "IAMUser",
            "identity_name": "bob",
            "source_ip": "203.0.113.11",
        }
        data.update(overrides)
        return Event(**data)

    return _make
