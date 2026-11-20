"""Score de risque 0-100 par fenêtre, alertes au format du contrat, et sortie JSON.

Règle de calcul (simple et explicable en soutenance) :
  - score de base = max(score de la meilleure règle, score ML x 100)
  - +10 si une règle ET le ML signalent la même fenêtre (confirmation croisée)
  - +5 par règle distincte supplémentaire sur la fenêtre (plafonné à +15)
  - résultat borné à 100

Utilisation (depuis la racine du projet) :
    python -m src.scoring.scoring --unseen persistence_access_key
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from src.detection.engine import run_rules
from src.detection.ml.features import build_features
from src.detection.ml.split import LABEL_COL, UNSEEN_SCENARIO, split_by_identity
from src.detection.ml.train import Params, score_windows, train
from src.evaluation.compare import _covered_keys, _get
from src.evaluation.metrics import compute_metrics
from src.ingestion.models import load_events
from src.scoring.correlation import correlate

ML_THRESHOLD = 50  # score ML (0-100) à partir duquel une fenêtre est signalée
BOTH_BONUS = 10
EXTRA_RULE_BONUS = 5
EXTRA_RULE_CAP = 15


def severity(score: float) -> str:
    if score >= 80:
        return "critique"
    if score >= 60:
        return "élevée"
    if score >= 40:
        return "moyenne"
    return "faible"


def _safe(alert: object, field: str, default: object) -> object:
    try:
        value = _get(alert, field)
    except (KeyError, AttributeError):
        return default
    return default if value is None else value


def window_scores(
    windows: pd.DataFrame, alerts: list, ml_scores: pd.Series, window: str = "1h"
) -> pd.DataFrame:
    """Une ligne par fenêtre avec score règles, score ML et score de risque final."""
    by_key: dict[tuple, dict[str, float]] = {}
    for alert in alerts:
        rule = str(_safe(alert, "rule_id", "RULE"))
        score = float(_safe(alert, "score", 50))
        for key in _covered_keys(alert, window):
            by_key.setdefault(key, {})[rule] = max(score, by_key.get(key, {}).get(rule, 0))

    starts = pd.to_datetime(windows["window_start"], utc=True)
    rows = []
    for idx, ident, start in zip(windows.index, windows["identity"], starts, strict=True):
        rules = by_key.get((ident, start), {})
        rule_score = max(rules.values(), default=0.0)
        ml = float(ml_scores.loc[idx]) * 100
        risk = max(rule_score, ml)
        if rules and ml >= ML_THRESHOLD:
            risk += BOTH_BONUS
        risk += min(EXTRA_RULE_BONUS * max(len(rules) - 1, 0), EXTRA_RULE_CAP)
        rows.append(
            {
                "identity": ident,
                "window_start": start,
                "rule_score": round(rule_score),
                "ml_score": round(ml),
                "n_rules": len(rules),
                "rules": ",".join(sorted(rules)),
                "risk_score": int(min(round(risk), 100)),
            }
        )
    return pd.DataFrame(rows, index=windows.index)


def build_alerts(alerts: list, scores: pd.DataFrame, window: str = "1h") -> list[dict]:
    """Alertes au format `docs/contracts.md` (rule, ml ou combined), triées par date."""
    lookup = {(r.identity, r.window_start): r for r in scores.itertuples()}
    out: list[dict] = []
    for alert in alerts:
        rows = [lookup[k] for k in _covered_keys(alert, window) if k in lookup]
        base = float(_safe(alert, "score", 50))
        score = max([base, *[r.risk_score for r in rows]])
        combined = any(r.ml_score >= ML_THRESHOLD for r in rows)
        out.append(
            {
                "identity": _get(alert, "identity"),
                "detection_source": "combined" if combined else "rule",
                "rule_id": str(_safe(alert, "rule_id", "RULE")),
                "mitre_technique": str(_safe(alert, "mitre_technique", "")),
                "score": int(min(score, 100)),
                "event_ids": list(_safe(alert, "event_ids", [])),
                "first_seen": str(_get(alert, "first_seen")),
                "last_seen": str(_get(alert, "last_seen")),
                "description": str(_safe(alert, "description", "")),
            }
        )
    ml_only = scores[(scores["ml_score"] >= ML_THRESHOLD) & (scores["n_rules"] == 0)]
    for r in ml_only.itertuples():
        end = r.window_start + pd.Timedelta(window)
        out.append(
            {
                "identity": r.identity,
                "detection_source": "ml",
                "rule_id": "ML-IF",
                "mitre_technique": "",
                "score": int(r.risk_score),
                "event_ids": [],
                "first_seen": r.window_start.isoformat(),
                "last_seen": end.isoformat(),
                "description": "Comportement anormal détecté par l'Isolation Forest",
            }
        )
    out.sort(key=lambda a: (pd.to_datetime(a["first_seen"], utc=True), a["identity"]))
    for i, alert in enumerate(out, start=1):
        alert["alert_id"] = f"a-{i:04d}"
    return [{"alert_id": a.pop("alert_id"), **a} for a in out]


def main() -> None:
    ap = argparse.ArgumentParser(description="Calcule les scores, alertes et incidents.")
    ap.add_argument("--logs", default="data/generated_ml/cloudtrail_logs.json")
    ap.add_argument("--labels", default="data/generated_ml/labels.csv")
    ap.add_argument("--window", default="1h")
    ap.add_argument("--unseen", default=UNSEEN_SCENARIO)
    ap.add_argument("--out", type=Path, default=Path("data/output"))
    args = ap.parse_args()

    events, _ = load_events(args.logs, args.labels)
    features = build_features(events, args.window)
    alerts = run_rules(events)
    split = split_by_identity(features, args.unseen)
    model = train(split.train, Params())
    ml = score_windows(model, features)

    scores = window_scores(features, alerts, ml, args.window)
    final = build_alerts(alerts, scores, args.window)
    incidents = correlate(final)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "alerts.json").write_text(
        json.dumps(final, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (args.out / "incidents.json").write_text(
        json.dumps(incidents, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    scores.assign(**{LABEL_COL: features[LABEL_COL]}).to_csv(
        args.out / "window_scores.csv", index=False
    )

    is_test = features["identity"].isin(set(split.test["identity"]))
    y_true = features.loc[is_test, LABEL_COL]
    print(f"{len(final)} alertes, {len(incidents)} incidents -> {args.out}")
    print(f"\nÉvaluation du score sur le test ({int(is_test.sum())} fenêtres) :")
    for threshold in (30, 50, 70):
        m = compute_metrics(y_true, (scores.loc[is_test, "risk_score"] >= threshold).astype(int))
        print(
            f"  seuil >= {threshold}: precision={m['precision']:.2f} "
            f"recall={m['recall']:.2f} F1={m['f1']:.2f} FPR={m['fpr']:.1%}"
        )

if __name__ == "__main__":
    main()
