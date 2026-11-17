"""Évaluation des règles de détection seules (sans machine learning).

Compare les alertes produites par les règles aux étiquettes du jeu de données
(`is_attack`, `scenario`) et calcule trois niveaux de résultats :
  - global : précision, rappel et F1 au niveau des événements ;
  - par règle : combien d'alertes, combien sont vraies ou fausses ;
  - par scénario : l'attaque est-elle détectée, et par quelles règles ?

Utilisation (depuis la racine du projet) :
    python -m src.evaluation.rules_eval
    python -m src.evaluation.rules_eval --markdown docs/evaluation_rules.md

Attention : les logs et les règles ont été conçus ensemble. Ces chiffres sont donc optimistes ;
leur valeur est de servir de point de départ pour comparer le machine learning, et de filet de
sécurité si une règle est modifiée.
"""
import argparse
from dataclasses import dataclass
from pathlib import Path

from src.detection.alerts import Alert
from src.detection.engine import run_rules
from src.detection.rules import RULES
from src.ingestion.models import Event, load_events

# Règles que chaque scénario est conçu pour déclencher.
TARGET_RULES = {
    "privilege_escalation": {"IAM-001", "IAM-005"},
    "credential_abuse": {"AUTH-002"},
    "iam_recon": {"IAM-006"},
    "defense_evasion": {"LOG-001"},
    "s3_exfiltration": {"S3-001"},
    "no_mfa_login": {"AUTH-001"},
    "persistence_access_key": {"IAM-004", "IAM-005"},
}


@dataclass
class Overall:
    events: int
    attack_events: int
    alerts: int
    tp: int
    fp: int
    fn: int
    precision: float | None
    recall: float | None
    f1: float | None


@dataclass
class RuleStats:
    rule_id: str
    alerts: int
    true_alerts: int
    false_alerts: int
    precision: float | None


@dataclass
class ScenarioStats:
    scenario: str
    events: int
    flagged: int
    recall: float | None
    detected: bool
    rules_fired: list[str]
    targets: list[str]
    targets_fired: list[str]


@dataclass
class Evaluation:
    overall: Overall
    rules: list[RuleStats]
    scenarios: list[ScenarioStats]


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def evaluate(
    events: list[Event], alerts: list[Alert], rule_ids: list[str] | None = None
) -> Evaluation:
    """Calcule les résultats globaux, par règle et par scénario."""
    rule_ids = rule_ids or [rule.RULE_ID for rule in RULES]
    by_id = {event.event_id: event for event in events}
    flagged_ids = {event_id for alert in alerts for event_id in alert.event_ids}
    attack_ids = {event.event_id for event in events if event.is_attack}

    tp = len(flagged_ids & attack_ids)
    fp = len(flagged_ids & (set(by_id) - attack_ids))
    fn = len(attack_ids - flagged_ids)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    overall = Overall(
        events=len(events),
        attack_events=len(attack_ids),
        alerts=len(alerts),
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=_f1(precision, recall),
    )

    rules = []
    for rule_id in rule_ids:
        mine = [alert for alert in alerts if alert.rule_id == rule_id]
        true_alerts = sum(
            any(by_id[i].is_attack for i in alert.event_ids if i in by_id) for alert in mine
        )
        rules.append(
            RuleStats(rule_id, len(mine), true_alerts, len(mine) - true_alerts,
                      _ratio(true_alerts, len(mine)))
        )

    scenarios = []
    names = sorted({e.scenario for e in events if e.is_attack}, key=_scenario_order)
    for name in names:
        scenario_ids = {e.event_id for e in events if e.scenario == name}
        flagged = len(scenario_ids & flagged_ids)
        fired = sorted(
            {alert.rule_id for alert in alerts if scenario_ids & set(alert.event_ids)}
        )
        targets = sorted(TARGET_RULES.get(name, set()))
        scenarios.append(
            ScenarioStats(
                scenario=name,
                events=len(scenario_ids),
                flagged=flagged,
                recall=_ratio(flagged, len(scenario_ids)),
                detected=flagged > 0,
                rules_fired=fired,
                targets=targets,
                targets_fired=[rule for rule in targets if rule in fired],
            )
        )
    return Evaluation(overall, rules, scenarios)


def _scenario_order(name: str) -> int:
    order = list(TARGET_RULES)
    return order.index(name) if name in order else len(order)


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.0%}"


def _tables(result: Evaluation) -> tuple[list[list[str]], list[list[str]]]:
    rule_rows = [
        [r.rule_id, str(r.alerts), str(r.true_alerts), str(r.false_alerts), _pct(r.precision)]
        for r in result.rules
    ]
    scenario_rows = [
        [
            s.scenario,
            str(s.events),
            str(s.flagged),
            _pct(s.recall),
            "oui" if s.detected else "NON",
            f"{len(s.targets_fired)}/{len(s.targets)} ({', '.join(s.rules_fired) or '-'})",
        ]
        for s in result.scenarios
    ]
    return rule_rows, scenario_rows


RULE_HEADERS = ["Règle", "Alertes", "Vraies", "Fausses", "Précision"]
SCENARIO_HEADERS = ["Scénario", "Événements", "Signalés", "Rappel", "Détecté",
                    "Règles cibles (règles déclenchées)"]


def _overall_line(o: Overall) -> str:
    return (
        f"Niveau événement : précision {_pct(o.precision)}, rappel {_pct(o.recall)}, "
        f"F1 {_pct(o.f1)} (vrais positifs {o.tp}, faux positifs {o.fp}, faux négatifs {o.fn})"
    )


def format_text(result: Evaluation) -> str:
    """Rapport lisible dans le terminal."""
    rule_rows, scenario_rows = _tables(result)

    def render(headers, rows):
        widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows, strict=False)]
        lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=False))]
        lines += ["  ".join(c.ljust(w) for c, w in zip(row, widths, strict=False)) for row in rows]
        return "\n".join(lines)

    o = result.overall
    return "\n".join([
        f"{o.events} événements, {o.attack_events} d'attaque, {o.alerts} alertes",
        _overall_line(o),
        "",
        "Par règle",
        render(RULE_HEADERS, rule_rows),
        "",
        "Par scénario",
        render(SCENARIO_HEADERS, scenario_rows),
    ])


def format_markdown(result: Evaluation) -> str:
    """Rapport au format Markdown, à placer dans docs/."""
    rule_rows, scenario_rows = _tables(result)

    def render(headers, rows):
        lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
        lines += ["| " + " | ".join(row) + " |" for row in rows]
        return "\n".join(lines)

    o = result.overall
    return "\n".join([
        "# Évaluation des règles de détection (sans machine learning)",
        "",
        f"{o.events} événements, {o.attack_events} d'attaque, {o.alerts} alertes.",
        "",
        _overall_line(o) + ".",
        "",
        "## Par règle",
        "",
        render(RULE_HEADERS, rule_rows),
        "",
        "## Par scénario",
        "",
        render(SCENARIO_HEADERS, scenario_rows),
        "",
        "> Limite : les logs synthétiques et les règles ont été conçus ensemble, ces chiffres "
        "sont donc optimistes. Ils servent de référence pour comparer le machine learning.",
        "",
    ])


def main() -> None:
    parser = argparse.ArgumentParser(description="Évalue les règles de détection")
    parser.add_argument("--logs", default="data/generated/cloudtrail_logs.json")
    parser.add_argument("--labels", default="data/generated/labels.csv")
    parser.add_argument("--markdown", default=None, help="écrit aussi le rapport en Markdown")
    args = parser.parse_args()

    events, _ = load_events(args.logs, args.labels)
    result = evaluate(events, run_rules(events))
    print(format_text(result))
    if args.markdown:
        path = Path(args.markdown)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(format_markdown(result), encoding="utf-8")
        print(f"\nRapport écrit dans {path}")


if __name__ == "__main__":
    main()
