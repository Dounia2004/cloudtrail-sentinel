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
BENIGN_SCENARIOS = {
    "benign_new_employee",
    "benign_audit_tool",
    "benign_backup_job",
    "benign_vpn_login",
    "benign_typo_logins",
}
EXTENDED_ARGS = ["--extended", "--users", "8", "--days", "14", "--attack-repeats", "2"]


def run_generator(out_dir, *extra, seed=42, check=True):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--seed", str(seed), "--out", str(out_dir), *extra],
        check=check,
        capture_output=True,
        text=True,
    )


def generate(out_dir, *extra, seed=42):
    run_generator(out_dir, *extra, seed=seed)


def read_labels(out_dir):
    with open(Path(out_dir) / "labels.csv", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def is_harmless(scenario):
    return scenario == "normal" or scenario.startswith("benign_")


# Mode de base --------------------------------------------------------------


def test_all_scenarios_are_generated(tmp_path):
    generate(tmp_path)
    counts = Counter(row["scenario"] for row in read_labels(tmp_path))
    assert counts["normal"] > 0
    for scenario, minimum in EXPECTED_MINIMUM.items():
        assert counts[scenario] >= minimum, scenario


def test_default_output_is_stable(tmp_path):
    """Le mode de base ne doit pas changer : les fixtures et l'évaluation en dépendent."""
    generate(tmp_path)
    rows = read_labels(tmp_path)
    assert len(rows) == 249
    assert sum(int(row["is_attack"]) for row in rows) == 64


def test_only_harmless_events_are_not_attacks(tmp_path):
    generate(tmp_path)
    for row in read_labels(tmp_path):
        assert is_harmless(row["scenario"]) == (row["is_attack"] == "0")


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


# Mode étendu ---------------------------------------------------------------


def test_extended_contains_every_scenario(tmp_path):
    generate(tmp_path, *EXTENDED_ARGS)
    counts = Counter(row["scenario"] for row in read_labels(tmp_path))
    for scenario, minimum in EXPECTED_MINIMUM.items():
        assert counts[scenario] >= 2 * minimum, scenario
    assert counts["crypto_mining"] >= 12
    for scenario in BENIGN_SCENARIOS:
        assert counts[scenario] > 0, scenario


def test_extended_labels_are_consistent(tmp_path):
    generate(tmp_path, *EXTENDED_ARGS)
    for row in read_labels(tmp_path):
        assert is_harmless(row["scenario"]) == (row["is_attack"] == "0")


def test_extended_is_reproducible(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    generate(first, *EXTENDED_ARGS)
    generate(second, *EXTENDED_ARGS)
    assert (first / "cloudtrail_logs.json").read_text(encoding="utf-8") == (
        second / "cloudtrail_logs.json"
    ).read_text(encoding="utf-8")


def test_extended_has_more_users_than_base(tmp_path):
    generate(tmp_path, *EXTENDED_ARGS)
    with open(tmp_path / "cloudtrail_logs.json", encoding="utf-8") as f:
        records = json.load(f)["Records"]
    normal_ids = {r["eventID"] for r in records} & {
        row["eventID"] for row in read_labels(tmp_path) if row["scenario"] == "normal"
    }
    users = {r["userIdentity"]["userName"] for r in records if r["eventID"] in normal_ids}
    assert len(users) == 8


def test_extended_logs_pass_validation(tmp_path):
    generate(tmp_path, *EXTENDED_ARGS)
    events, rejected = load_events(tmp_path / "cloudtrail_logs.json", tmp_path / "labels.csv")
    assert rejected == []
    assert len(events) == len(read_labels(tmp_path))


def test_extended_needs_enough_days(tmp_path):
    result = run_generator(tmp_path, "--extended", "--days", "3", check=False)
    assert result.returncode != 0


def test_extended_options_require_the_flag(tmp_path):
    result = run_generator(tmp_path, "--users", "10", check=False)
    assert result.returncode != 0
