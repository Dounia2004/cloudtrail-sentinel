"""Checklist de sécurité du dépôt, vérifiée à chaque exécution de la CI.

Les fausses valeurs ci-dessous sont assemblées à l'exécution : écrites en clair, elles seraient
elles-mêmes signalées par l'audit (et par gitleaks).
"""
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

import audit_repo  # noqa: E402

REAL_IP = ".".join(["8", "8", "8", "8"])
REAL_ACCOUNT = "2109" + "87654321"
REAL_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
EXAMPLE_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"


def _in_git_repo() -> bool:
    result = subprocess.run(["git", "rev-parse"], capture_output=True)
    return result.returncode == 0


def test_no_secret_real_ip_or_forbidden_file_is_tracked():
    if not _in_git_repo():
        pytest.skip("pas dans un dépôt git")
    assert audit_repo.find_problems() == []


def test_detects_real_ip_account_and_key(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text(
        f"ip {REAL_IP}\narn:aws:iam::{REAL_ACCOUNT}:user/x\nkey {REAL_KEY}\n",
        encoding="utf-8",
    )
    problems = audit_repo.find_problems([str(bad)])
    assert len(problems) == 3


def test_accepts_documentation_values(tmp_path):
    good = tmp_path / "good.txt"
    good.write_text(
        "ip 203.0.113.5 198.51.100.9 192.0.2.7\narn:aws:iam::123456789012:user/x\n"
        f"key {EXAMPLE_KEY}\n",
        encoding="utf-8",
    )
    assert audit_repo.find_problems([str(good)]) == []


def test_flags_forbidden_files():
    assert audit_repo.find_problems([".env"]) != []
    assert audit_repo.find_problems(["data/sentinel.db"]) != []
