"""Prépare les données de démonstration : logs synthétiques -> SQLite -> scores et alertes.

Utilisé par `docker compose up` (service `bootstrap`), mais fonctionne aussi à la main :
    python scripts/bootstrap.py            # ne refait rien si data/output/alerts.json existe
    python scripts/bootstrap.py --force    # régénère tout
Les paramètres sont ceux du rapport d'évaluation (graine 7, 10 répétitions d'attaque).
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

DATA = Path("data/generated_ml")
LOGS = DATA / "cloudtrail_logs.json"
LABELS = DATA / "labels.csv"
OUTPUT = Path("data/output")
SEED = "7"
ATTACK_REPEATS = "10"
UNSEEN = "persistence_access_key"
ML_THRESHOLD = "85"
ML_ONLY_CAP = "59"


def step(title: str, command: list[str]) -> None:
    print(f"\n=== {title} ===", flush=True)
    start = time.time()
    subprocess.run([sys.executable, *command], check=True)
    print(f"({time.time() - start:.1f} s)", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prépare les données de démonstration")
    parser.add_argument("--force", action="store_true", help="régénère même si déjà prêt")
    args = parser.parse_args()

    if (OUTPUT / "alerts.json").exists() and not args.force:
        print("Données déjà prêtes (utilisez --force pour régénérer).")
        return

    step(
        "1/3 Génération des logs synthétiques",
        [
            "scripts/generate_data.py",
            "--extended",
            "--seed",
            SEED,
            "--attack-repeats",
            ATTACK_REPEATS,
            "--out",
            str(DATA),
        ],
    )

    # Base neuve : l'ingestion ignore les doublons, mais on repart de zéro pour rester cohérent.
    for db in Path("data").glob("*.db"):
        db.unlink()
    step(
        "2/3 Ingestion dans SQLite",
        ["-m", "src.ingestion.run", "--logs", str(LOGS), "--labels", str(LABELS)],
    )

    step(
        "3/3 Détection, scoring et corrélation",
        [
            "-m",
            "src.scoring.scoring",
            "--logs",
            str(LOGS),
            "--labels",
            str(LABELS),
            "--unseen",
            UNSEEN,
            "--ml-threshold",
            ML_THRESHOLD,
            "--ml-only-cap",
            ML_ONLY_CAP,
            "--out",
            str(OUTPUT),
        ],
    )
    print("\nPrêt : API sur :8000, dashboard sur :8501.")


if __name__ == "__main__":
    main()
