"""Validation sur données réelles : que font l'ingestion, les règles et les features sur des
logs CloudTrail publics (flaws.cloud) ?

Ces logs ne sont pas étiquetés : il n'y a donc pas de precision ni de recall, seulement un
contrôle de robustesse (événements rejetés) et un aperçu qualitatif (alertes par règle).

Utilisation (après scripts/download_public_data.py) :
    python -m src.evaluation.public_check
    python -m src.evaluation.public_check --out docs/public_data.md
"""
import argparse
from collections import Counter
from pathlib import Path

from src.detection.engine import run_rules
from src.detection.ml.features import build_features
from src.ingestion.models import load_events

TOP = 10


def check(logs_path: str | Path, window: str = "1h") -> dict:
    events, rejected = load_events(logs_path)
    alerts = run_rules(events) if events else []
    features = build_features(events, window) if events else None
    total = len(events) + len(rejected)
    return {
        "total": total,
        "valid": len(events),
        "rejected": len(rejected),
        "reject_reasons": Counter(r["error"] for r in rejected).most_common(TOP),
        "windows": 0 if features is None else len(features),
        "identities": 0 if features is None else int(features["identity"].nunique()),
        "alerts": len(alerts),
        "alerts_by_rule": Counter(a.rule_id for a in alerts).most_common(),
        "top_events": Counter(e.event_name for e in events).most_common(TOP),
    }


def to_markdown(result: dict, source: str) -> str:
    rate = result["valid"] / result["total"] if result["total"] else 0
    lines = [
        "# Validation sur données publiques (flaws.cloud)",
        "",
        f"Source : {source}. Logs réels anonymisés, **non étiquetés** : pas de precision ni de "
        "recall, seulement un contrôle de robustesse et un aperçu qualitatif.",
        "",
        f"- Événements lus : {result['total']}, valides : {result['valid']} ({rate:.1%}), "
        f"rejetés : {result['rejected']}",
        f"- Fenêtres (identité x heure) : {result['windows']} "
        f"pour {result['identities']} identités",
        f"- Alertes des règles : {result['alerts']}",
        "",
        "## Alertes par règle",
        "",
        "| Règle | Alertes |",
        "|---|---|",
        *[f"| {rule} | {n} |" for rule, n in result["alerts_by_rule"]],
        "",
        "## Événements les plus fréquents",
        "",
        "| Événement | Occurrences |",
        "|---|---|",
        *[f"| {name} | {n} |" for name, n in result["top_events"]],
    ]
    if result["reject_reasons"]:
        lines += [
            "",
            "## Motifs de rejet",
            "",
            "| Motif | Occurrences |",
            "|---|---|",
            *[f"| {reason} | {n} |" for reason, n in result["reject_reasons"]],
        ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Contrôle sur logs CloudTrail publics")
    parser.add_argument("--logs", default="data/public/flaws_cloudtrail_sample.json")
    parser.add_argument("--window", default="1h")
    parser.add_argument("--out", type=Path, default=None, help="écrit un rapport Markdown")
    args = parser.parse_args()

    result = check(args.logs, args.window)
    report = to_markdown(result, "Summit Route, flaws.cloud CloudTrail logs (2020)")
    print(report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"Rapport écrit dans {args.out}")


if __name__ == "__main__":
    main()
