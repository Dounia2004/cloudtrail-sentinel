"""Chaîne d'ingestion : fichier CloudTrail -> validation -> normalisation -> SQLite.

Utilisation (depuis la racine du projet) :
    python -m src.ingestion.run
"""
import argparse

from src.ingestion.models import load_events
from src.storage.db import connect, count_events, init_db, insert_events


def main() -> None:
    parser = argparse.ArgumentParser(description="Importe des logs CloudTrail dans SQLite")
    parser.add_argument("--logs", default="data/generated/cloudtrail_logs.json")
    parser.add_argument("--labels", default="data/generated/labels.csv")
    parser.add_argument("--db", default=None, help="chemin SQLite (sinon DATABASE_URL)")
    args = parser.parse_args()

    events, rejected = load_events(args.logs, args.labels)

    conn = connect(args.db)
    init_db(conn)
    inserted = insert_events(conn, events)

    print(f"{len(events)} événements valides, {len(rejected)} rejetés")
    print(f"{inserted} nouveaux événements enregistrés ({count_events(conn)} au total)")
    for item in rejected[:5]:
        print("rejeté :", item)
    conn.close()


if __name__ == "__main__":
    main()
