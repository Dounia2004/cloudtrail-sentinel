"""Comparaison règles seules / ML seul / approche combinée, sur le même jeu de test.

Les règles produisent des alertes (identité + période). On les ramène à la fenêtre
(identité x heure) pour les évaluer avec exactement les mêmes métriques que le ML.

Utilisation (depuis la racine du projet) :
    python -m src.evaluation.compare --unseen persistence_access_key
"""
from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from src.detection.engine import run_rules
from src.detection.ml.features import build_features
from src.detection.ml.split import LABEL_COL, SEED, UNSEEN_SCENARIO, split_by_identity
from src.detection.ml.supervised import predict_supervised, train_supervised
from src.detection.ml.train import Params, predict, train, tune
from src.evaluation.metrics import (
    by_scenario,
    compute_metrics,
    confusion_matrix,
    evaluate_models,
    to_markdown,
)
from src.ingestion.models import load_events


def _get(alert: object, field: str):
    """Lit un champ d'alerte, que l'alerte soit un objet ou un dictionnaire."""
    if isinstance(alert, dict):
        return alert[field]
    return getattr(alert, field)


def _utc(value: object) -> pd.Timestamp:
    return pd.to_datetime(value, utc=True)


def _window_keys(df: pd.DataFrame) -> pd.Series:
    start = pd.to_datetime(df["window_start"], utc=True)
    return pd.Series(list(zip(df["identity"], start, strict=True)), index=df.index)


def _covered_keys(alert: object, window: str) -> list[tuple[str, pd.Timestamp]]:
    first = _utc(_get(alert, "first_seen")).floor(window)
    last = _utc(_get(alert, "last_seen")).floor(window)
    identity = _get(alert, "identity")
    return [(identity, ts) for ts in pd.date_range(first, last, freq=window)]


def alerts_to_windows(alerts: list, windows: pd.DataFrame, window: str = "1h") -> pd.Series:
    """1 si au moins une alerte couvre la fenêtre (même identité, même heure), sinon 0."""
    flagged: set[tuple[str, pd.Timestamp]] = set()
    for alert in alerts:
        flagged.update(_covered_keys(alert, window))
    flags = _window_keys(windows).map(lambda k: int(k in flagged))
    return flags.rename("rules_pred")


def alerts_by_rule(alerts: list, windows: pd.DataFrame, window: str = "1h") -> pd.DataFrame:
    """Par règle : combien d'alertes touchent une fenêtre d'attaque ou une fenêtre normale.

    Sert à documenter les faux positifs de chaque règle (cahier des charges, section 9).
    """
    attack_by_key = dict(zip(_window_keys(windows), windows[LABEL_COL], strict=True))
    rows: dict[str, dict[str, int]] = {}
    for alert in alerts:
        rule = str(_get(alert, "rule_id"))
        keys = [k for k in _covered_keys(alert, window) if k in attack_by_key]
        on_attack = any(attack_by_key[k] == 1 for k in keys)
        stats = rows.setdefault(rule, {"alertes": 0, "sur_attaque": 0, "sur_normal": 0})
        stats["alertes"] += 1
        if on_attack:
            stats["sur_attaque"] += 1
        elif keys:
            stats["sur_normal"] += 1
    out = pd.DataFrame.from_dict(rows, orient="index").rename_axis("règle").reset_index()
    return out.sort_values("règle").reset_index(drop=True) if len(out) else out


def combine(rules_pred: pd.Series, ml_pred: pd.Series) -> pd.Series:
    """Approche combinée : une fenêtre est signalée si les règles OU le ML la signalent."""
    return (rules_pred.astype(int) | ml_pred.astype(int)).rename("combined_pred")


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare règles, ML et approche combinée.")
    ap.add_argument("--logs", default="data/generated_ml/cloudtrail_logs.json")
    ap.add_argument("--labels", default="data/generated_ml/labels.csv")
    ap.add_argument("--window", default="1h")
    ap.add_argument("--unseen", default=UNSEEN_SCENARIO)
    ap.add_argument("--tune", action="store_true", help="réglage des hyperparamètres")
    ap.add_argument("--out", type=Path, default=None, help="écrit un rapport Markdown")
    args = ap.parse_args()

    events, _ = load_events(args.logs, args.labels)
    features = build_features(events, args.window)
    alerts = run_rules(events)
    split = split_by_identity(features, args.unseen, seed=SEED)
    test = split.test

    iso = train(split.train, tune(split.train) if args.tune else Params())
    rf = train_supervised(split.train)
    preds = {
        "règles": alerts_to_windows(alerts, test, args.window),
        "isolation_forest": predict(iso, test),
    }
    preds["combiné (règles OU IF)"] = combine(preds["règles"], preds["isolation_forest"])
    preds["random_forest (réf.)"] = predict_supervised(rf, test)

    overall = evaluate_models(test, preds)
    scenarios = by_scenario(test, preds)
    rules_table = alerts_by_rule(alerts, test, args.window)

    n_attack = int(test[LABEL_COL].sum())
    print(f"Test : {len(test)} fenêtres dont {n_attack} d'attaque")
    print(f"Scénario non vu à l'entraînement : {args.unseen}")
    print("\nMétriques globales :")
    print(overall.round(3).to_string(index=False))
    print("\nPart des fenêtres signalées par scénario :")
    print(scenarios.to_string(index=False))
    print("\nAlertes par règle (sur le jeu de test) :")
    print(rules_table.to_string(index=False) if len(rules_table) else "aucune alerte")

    if args.out:
        parts = [
            "# Résultats d'évaluation",
            f"Test : {len(test)} fenêtres, dont {n_attack} d'attaque. "
            f"Scénario non vu à l'entraînement : `{args.unseen}`.",
            "## Métriques globales",
            to_markdown(overall),
            "## Part de fenêtres signalées par scénario",
            to_markdown(scenarios),
            "## Matrices de confusion",
        ]
        for name, pred in preds.items():
            cm = confusion_matrix(compute_metrics(test[LABEL_COL], pred))
            cm_table = cm.reset_index().rename(columns={"index": " "})
            parts += [f"### {name}", to_markdown(cm_table)]
        parts += ["## Alertes par règle", to_markdown(rules_table) if len(rules_table) else "-"]
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text("\n\n".join(parts) + "\n", encoding="utf-8")
        print(f"\nRapport écrit dans {args.out}")


if __name__ == "__main__":
    main()
