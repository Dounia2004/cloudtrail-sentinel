"""Audit de sécurité du dépôt : secrets, données fictives, fichiers interdits, licences.

Utilisation :
    python scripts/audit_repo.py          # affiche le rapport, code de sortie 1 si problème
Le test tests/test_audit.py exécute les mêmes vérifications en CI.
"""
import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path

# Plages d'adresses réservées à la documentation (RFC 5737) + boucle locale.
ALLOWED_IP = re.compile(r"^(203\.0\.113\.|198\.51\.100\.|192\.0\.2\.|127\.|0\.0\.0\.0$)")
IP = re.compile(r"(?<![\w.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\w.])")
ACCOUNT_ID = re.compile(r"arn:aws:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):")
ACCESS_KEY = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
FAKE_ACCOUNT = "123456789012"
FORBIDDEN_NAMES = {".env"}
FORBIDDEN_SUFFIXES = {".db", ".sqlite", ".joblib", ".pkl", ".pem", ".key"}
SKIP_SUFFIXES = {".png", ".jpg", ".gif", ".pdf", ".ico", ".zip"}
SELF = "scripts/audit_repo.py"


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True, encoding="utf-8"
    )
    return [line for line in out.stdout.splitlines() if line]


def find_problems(files: list[str] | None = None) -> list[str]:
    problems = []
    for name in files if files is not None else tracked_files():
        path = Path(name)
        if path.name in FORBIDDEN_NAMES or path.suffix in FORBIDDEN_SUFFIXES:
            problems.append(f"{name}: fichier qui ne doit pas être versionné")
            continue
        if name == SELF or path.suffix in SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            for ip in IP.findall(line):
                octets = ip.split(".")
                if all(int(o) <= 255 for o in octets) and not ALLOWED_IP.match(ip):
                    problems.append(f"{name}:{number}: IP hors plages de documentation ({ip})")
            for account in ACCOUNT_ID.findall(line):
                if account != FAKE_ACCOUNT:
                    problems.append(f"{name}:{number}: identifiant de compte AWS ({account})")
            for match in ACCESS_KEY.finditer(line):
                if not match.group(0).endswith("EXAMPLE"):
                    problems.append(f"{name}:{number}: clé d'accès AWS possible")
    return problems


def dependency_licenses(requirements: str = "requirements.txt") -> dict[str, str]:
    """Licence déclarée de chaque dépendance directe (pour le rapport)."""
    result = {}
    for line in Path(requirements).read_text(encoding="utf-8").splitlines():
        name = re.split(r"[<>=!~\[ ]", line.strip(), maxsplit=1)[0]
        if not name or name.startswith("#"):
            continue
        try:
            meta = metadata.metadata(name)
        except metadata.PackageNotFoundError:
            result[name] = "non installé"
            continue
        license_ = meta.get("License-Expression") or meta.get("License") or ""
        if not license_ or len(license_) > 60:
            classifiers = [c for c in meta.get_all("Classifier", []) if c.startswith("License ::")]
            license_ = classifiers[0].split("::")[-1].strip() if classifiers else "inconnue"
        result[name] = license_
    return result


def main() -> int:
    problems = find_problems()
    status = "OK" if not problems else f"{len(problems)} problème(s)"
    print("Audit des fichiers versionnés :", status)
    for problem in problems[:30]:
        print("  -", problem)
    print("\nLicences des dépendances directes :")
    for name, license_ in sorted(dependency_licenses().items()):
        print(f"  {name:<14} {license_}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
