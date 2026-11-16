"""Crée les fixtures de test : un petit jeu de logs étiqueté, figé dans tests/fixtures/.

Les fixtures sont committées : elles ne changent plus, même si le générateur évolue.
À relancer uniquement pour les recréer volontairement :
    python scripts/make_fixtures.py

Contenu : un jour d'activité normale + les 7 scénarios d'attaque (S3 réduit à 16 événements).
"""
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate_data.py"
OUT = ROOT / "tests" / "fixtures"
FIRST_DAY = "2026-11-10"  # on garde uniquement ce jour pour l'activité normale
S3_LIMIT = 16  # 1 ListBuckets + 15 GetObject


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [sys.executable, str(GENERATOR), "--seed", "42", "--out", tmp],
            check=True,
            capture_output=True,
        )
        with open(Path(tmp) / "cloudtrail_logs.json", encoding="utf-8") as f:
            records = json.load(f)["Records"]
        with open(Path(tmp) / "labels.csv", newline="", encoding="utf-8") as f:
            labels = {row["eventID"]: row for row in csv.DictReader(f)}

    selected, s3_count = [], 0
    for record in records:  # déjà triés par date
        label = labels[record["eventID"]]
        scenario = label["scenario"]
        if scenario == "normal":
            if not record["eventTime"].startswith(FIRST_DAY):
                continue
        elif scenario == "s3_exfiltration":
            s3_count += 1
            if s3_count > S3_LIMIT:
                continue
        selected.append((record, label))

    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "cloudtrail_sample.json", "w", encoding="utf-8") as f:
        json.dump({"Records": [r for r, _ in selected]}, f, indent=2)
    with open(OUT / "labels_sample.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["eventID", "scenario", "is_attack"])
        for _, label in selected:
            writer.writerow([label["eventID"], label["scenario"], label["is_attack"]])

    attacks = sum(int(label["is_attack"]) for _, label in selected)
    print(f"{len(selected)} événements écrits ({attacks} d'attaque) dans {OUT}")


if __name__ == "__main__":
    main()
