import pytest

from src.storage.db import connect, count_events, fetch_events, get_db_path, init_db, insert_events


def make_event(event_id, when, identity="bob", name="ListBuckets", **extra):
    event = {
        "event_id": event_id,
        "event_time": when,
        "event_source": "s3.amazonaws.com",
        "event_name": name,
        "aws_region": "us-east-1",
        "identity_type": "IAMUser",
        "identity_name": identity,
        "source_ip": "203.0.113.11",
        "scenario": "normal",
        "is_attack": 0,
    }
    event.update(extra)
    return event


@pytest.fixture
def conn():
    connection = connect(":memory:")
    init_db(connection)
    yield connection
    connection.close()


def test_insert_and_count(conn):
    events = [make_event("e-1", "2026-11-10T09:00:00Z"), make_event("e-2", "2026-11-10T10:00:00Z")]
    assert insert_events(conn, events) == 2
    assert count_events(conn) == 2


def test_reinsert_does_not_create_duplicates(conn):
    events = [make_event("e-1", "2026-11-10T09:00:00Z")]
    insert_events(conn, events)
    assert insert_events(conn, events) == 0
    assert count_events(conn) == 1


def test_fetch_filters_and_orders(conn):
    insert_events(conn, [
        make_event("e-2", "2026-11-10T10:00:00Z", identity="alice"),
        make_event("e-1", "2026-11-10T09:00:00Z", identity="bob"),
        make_event("e-3", "2026-11-10T11:00:00Z", identity="bob", name="CreateUser"),
    ])
    bob = fetch_events(conn, identity="bob")
    assert [e["event_id"] for e in bob] == ["e-1", "e-3"]
    created = fetch_events(conn, event_name="CreateUser")
    assert [e["event_id"] for e in created] == ["e-3"]
    recent = fetch_events(conn, start="2026-11-10T10:00:00Z")
    assert [e["event_id"] for e in recent] == ["e-2", "e-3"]


def test_database_url_is_read_from_environment(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///data/test.db")
    assert get_db_path() == "data/test.db"
    monkeypatch.setenv("DATABASE_URL", "postgresql://user@host/db")
    with pytest.raises(ValueError):
        get_db_path()
