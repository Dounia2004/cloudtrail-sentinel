"""Random Forest supervisé (comparaison) et tableau Isolation Forest vs Random Forest.

Le Random Forest voit les étiquettes d'entraînement : il sert de référence pour montrer
ce que l'approche non supervisée apporte, surtout sur le scénario jamais vu.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

from src.detection.ml.features import FEATURE_COLUMNS
from src.detection.ml.split import (
    LABEL_COL,
    SCENARIO_COL,
    SEED,
    UNSEEN_SCENARIO,
    split_by_identity,
)
from src.detection.ml.train import Params, predict, train


@dataclass
class SupervisedModel:
    forest: RandomForestClassifier
    feature_cols: list[str]


def train_supervised(
    train_df: pd.DataFrame, n_estimators: int = 200, seed: int = SEED
) -> SupervisedModel:
    if train_df[LABEL_COL].nunique() < 2:
        raise ValueError("Le jeu d'entraînement doit contenir normal ET attaque.")
    cols = list(FEATURE_COLUMNS)
    forest = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight="balanced",
        random_state=seed,
        n_jobs=1,
    )
    forest.fit(train_df[cols].fillna(0), train_df[LABEL_COL])
    return SupervisedModel(forest, cols)


def score_supervised(model: SupervisedModel, df: pd.DataFrame) -> pd.Series:
    """Probabilité d'attaque dans [0, 1]."""
    proba = model.forest.predict_proba(df[model.feature_cols].fillna(0))[:, 1]
    return pd.Series(proba, index=df.index, name="rf_score")


def predict_supervised(model: SupervisedModel, df: pd.DataFrame) -> pd.Series:
    pred = (score_supervised(model, df) >= 0.5).astype(int)
    return pred.rename("rf_pred")


def compare(test: pd.DataFrame, preds: dict[str, pd.Series], unseen: str) -> pd.DataFrame:
    """Part de fenêtres signalées par scénario, pour chaque modèle."""
    rows = []
    for scen, part in test.groupby(SCENARIO_COL):
        row = {"scénario": scen, "fenêtres": len(part)}
        row["type"] = "attaque" if part[LABEL_COL].max() == 1 else "normal"
        for name, pred in preds.items():
            row[name] = round(float(pred.loc[part.index].mean()), 3)
        row["non vu"] = "oui" if scen == unseen else ""
        rows.append(row)
    return pd.DataFrame(rows).sort_values(["type", "scénario"]).reset_index(drop=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare Isolation Forest et Random Forest.")
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--unseen", default=UNSEEN_SCENARIO)
    ap.add_argument("--out", type=Path, default=None, help="écrit le tableau en CSV")
    args = ap.parse_args()

    df = pd.read_parquet(args.input) if args.input.suffix == ".parquet" else pd.read_csv(args.input)
    split = split_by_identity(df, args.unseen)

    iso = train(split.train, Params())
    rf = train_supervised(split.train)
    preds = {
        "isolation_forest": predict(iso, split.test),
        "random_forest": predict_supervised(rf, split.test),
    }

    y = split.test[LABEL_COL]
    normal = y == 0
    print("Métriques globales sur le test :")
    for name, pred in preds.items():
        f1 = f1_score(y, pred, zero_division=0)
        fpr = pred[normal].mean()
        print(f"  {name:<18} F1={f1:.3f}  taux de faux positifs={fpr:.1%}")

    table = compare(split.test, preds, args.unseen)
    print("\nPart des fenêtres signalées, par scénario :")
    print(table.to_string(index=False))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        table.to_csv(args.out, index=False)
        print(f"\nTableau écrit dans {args.out}")


if __name__ == "__main__":
    main()
