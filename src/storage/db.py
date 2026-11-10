"""Stockage SQLite : création de la table `events` et accès aux données.

Le schéma suit docs/contracts.md. L'emplacement de la base se règle avec la variable
d'environnement DATABASE_URL (par défaut : sqlite:///data/sentinel.db).
"""
import os
import sqlite3
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv est optionnel
    pass

DEFAULT_URL = "sqlite:///data/sentinel.db"

COLUMNS = [
    "event_id", "event_time", "event_source", "event_name", "aws_region",
    "identity_type", "identity_name", "identity_arn", "source_ip", "user_agent",
    "mfa_used", "error_code", "login_result", "request_params", "scenario", "is_attack",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id       TEXT PRIMARY KEY,
    event_time     TEXT NOT NULL,
    event_source   TEXT NOT NULL,
    event_name     TEXT NOT NULL,
    aws_region     TEXT,
    identity_type  TEXT,
    identity_name  TEXT NOT NULL,
    identity_arn   TEXT,
    source_ip      TEXT,
    user_agent     TEXT,
    mfa_used       INTEGER,
    error_code     TEXT,
    login_result   TEXT,
    request_params TEXT,
    scenario       TEXT,
    is_attack      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_identity_time ON events (identity_name, event_time);
CREATE INDEX IF NOT EXISTS idx_events_name ON events (event_name);
"""


def get_db_path() -> str:
    """Lit DATABASE_URL et retourne le chemin du fichier SQLite."""
    url = os.getenv("DATABASE_URL", DEFAULT_URL)
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        raise ValueError("Seule une base SQLite est gérée pour l'instant (sqlite:///...).")
    return url[len(prefix):]


def connect(db_path: str | None = None) -> sqlite3.Connection:
    """Ouvre la base (la crée si besoin). Utiliser ':memory:' pour les tests."""
    path = db_path or get_db_path()
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Crée la table `events` et ses index si elle n'existe pas."""
    conn.executescript(SCHEMA)
    conn.commit()


def count_events(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


def insert_events(conn: sqlite3.Connection, events) -> int:
    """Enregistre des événements (objets Pydantic ou dictionnaires).

    Un événement déjà présent (même event_id) est ignoré : relancer l'import
    ne crée donc pas de doublons. Retourne le nombre de nouveaux événements.
    """
    rows = []
    for event in events:
        data = event if isinstance(event, dict) else event.model_dump()
        rows.append([data.get(column) for column in COLUMNS])

    before = count_events(conn)
    placeholders = ", ".join("?" for _ in COLUMNS)
    conn.executemany(
        f"INSERT OR IGNORE INTO events ({', '.join(COLUMNS)}) VALUES ({placeholders})",
        rows,
    )
    conn.commit()
    return count_events(conn) - before


def fetch_events(
    conn: sqlite3.Connection,
    identity: str | None = None,
    event_name: str | None = None,
    start: str | None = None,
    end: str | None = None,
) -> list[dict]:
    """Retourne les événements filtrés, triés par date."""
    conditions, params = [], []
    if identity:
        conditions.append("identity_name = ?")
        params.append(identity)
    if event_name:
        conditions.append("event_name = ?")
        params.append(event_name)
    if start:
        conditions.append("event_time >= ?")
        params.append(start)
    if end:
        conditions.append("event_time <= ?")
        params.append(end)

    query = "SELECT * FROM events"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY event_time"
    return [dict(row) for row in conn.execute(query, params).fetchall()]
