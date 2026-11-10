import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from src.ingestion.models import load_events

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_data.py"

EXPECTED_MINIMUM = {
    "privilege_escalation": 3,
    "credential_abuse": 7,
    "iam_recon": 8,
    "defense_evasion": 2,
    "s3_exfiltration": 41,
    "no_mfa_login": 1,
    "persistence_access_key": 2,
}


def generate(out_dir, seed=42):
    subprocess.run(
        [sys.executable, str(SCRIPT), "--seed", str(seed), "--out", str(out_dir)],
        check=True,
        capture_output=True,
    )


def read_labels(out_dir):
    with open(Path(out_dir) / "labels.csv", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_all_scenarios_are_generated(tmp_path):
    generate(tmp_path)
    counts = Counter(row["scenario"] for row in read_labels(tmp_path))
    assert counts["normal"] > 0
    for scenario, minimum in EXPECTED_MINIMUM.items():
        assert counts[scenario] >= minimum, scenario


def test_only_normal_events_are_not_attacks(tmp_path):
    generate(tmp_path)
    for row in read_labels(tmp_path):
        assert (row["scenario"] == "normal") == (row["is_attack"] == "0")


def test_generation_is_reproducible(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    generate(first)
    generate(second)
    assert (first / "cloudtrail_logs.json").read_text(encoding="utf-8") == (
        second / "cloudtrail_logs.json"
    ).read_text(encoding="utf-8")


def test_event_ids_are_unique(tmp_path):
    generate(tmp_path)
    with open(tmp_path / "cloudtrail_logs.json", encoding="utf-8") as f:
        records = json.load(f)["Records"]
    ids = [r["eventID"] for r in records]
    assert len(ids) == len(set(ids))


def test_generated_logs_pass_validation(tmp_path):
    generate(tmp_path)
    events, rejected = load_events(tmp_path / "cloudtrail_logs.json", tmp_path / "labels.csv")
    assert rejected == []
    assert len(events) == len(read_labels(tmp_path))
