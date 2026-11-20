"""Métriques d'évaluation : precision, recall, F1, matrice de confusion, taux de faux positifs.

L'unité d'évaluation est la fenêtre (identité x heure). Les fonctions acceptent n'importe
quelle prédiction binaire (règles, Isolation Forest, Random Forest, approche combinée),
ce qui permet de comparer les approches avec exactement les mêmes calculs.
"""
from __future__ import annotations

import pandas as pd

LABEL_COL = "is_attack"
SCENARIO_COL = "scenario"


def _ratio(num: float, den: float) -> float:
    return float(num / den) if den else 0.0


def compute_metrics(y_true: pd.Series, y_pred: pd.Series) -> dict[str, float]:
    """Matrice de confusion et métriques pour une prédiction binaire (1 = attaque)."""
    t = pd.Series(y_true).astype(int).reset_index(drop=True)
    p = pd.Series(y_pred).astype(int).reset_index(drop=True)
    if len(t) != len(p):
        raise ValueError("y_true et y_pred n'ont pas la même longueur.")
    tp = int(((t == 1) & (p == 1)).sum())
    fp = int(((t == 0) & (p == 1)).sum())
    tn = int(((t == 0) & (p == 0)).sum())
    fn = int(((t == 1) & (p == 0)).sum())
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": _ratio(2 * precision * recall, precision + recall),
        "fpr": _ratio(fp, fp + tn),
    }


def confusion_matrix(m: dict[str, float]) -> pd.DataFrame:
    """Matrice de confusion lisible à partir du résultat de compute_metrics."""
    return pd.DataFrame(
        [[m["tn"], m["fp"]], [m["fn"], m["tp"]]],
        index=["réel : normal", "réel : attaque"],
        columns=["prédit : normal", "prédit : attaque"],
    ).astype(int)


def evaluate_models(test: pd.DataFrame, preds: dict[str, pd.Series]) -> pd.DataFrame:
    """Une ligne par modèle : mêmes métriques, mêmes données de test."""
    rows = []
    for name, pred in preds.items():
        m = compute_metrics(test[LABEL_COL], pred.loc[test.index])
        rows.append({"modèle": name, **m})
    return pd.DataFrame(rows)


def by_scenario(test: pd.DataFrame, preds: dict[str, pd.Series]) -> pd.DataFrame:
    """Part de fenêtres signalées par scénario.

    Pour un scénario d'attaque, c'est le rappel. Pour un scénario normal ou bénin,
    c'est le taux de faux positifs.
    """
    rows = []
    for scen, part in test.groupby(SCENARIO_COL):
        kind = "attaque" if part[LABEL_COL].max() == 1 else "normal"
        row = {"scénario": scen, "type": kind, "fenêtres": len(part)}
        for name, pred in preds.items():
            row[name] = round(float(pred.loc[part.index].mean()), 3)
        rows.append(row)
    return pd.DataFrame(rows).sort_values(["type", "scénario"]).reset_index(drop=True)


def to_markdown(table: pd.DataFrame, digits: int = 3) -> str:
    """Tableau Markdown (pour docs/evaluation.md), sans dépendance externe."""

    def fmt(v: object) -> str:
        return f"{v:.{digits}f}" if isinstance(v, float) else str(v)

    head = "| " + " | ".join(map(str, table.columns)) + " |"
    sep = "|" + "|".join("---" for _ in table.columns) + "|"
    body = ["| " + " | ".join(fmt(v) for v in row) + " |" for row in table.itertuples(index=False)]
    return "\n".join([head, sep, *body])
