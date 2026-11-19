"""Entraînement et utilisation de l'Isolation Forest (non supervisé).

Le modèle est entraîné uniquement sur les fenêtres normales du jeu d'entraînement.
Le score d'anomalie est normalisé entre 0 et 1 (1 = très anormal).
"""
from __future__ import annotations

import argparse
import itertools
import json
from dataclasses import asdict, dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.detection.ml.split import (
    IDENTITY_COL,
    LABEL_COL,
    SCENARIO_COL,
    SEED,
    split_by_identity,
)

MODEL_DIR = Path("models")
META_COLS = {IDENTITY_COL, LABEL_COL, SCENARIO_COL, "window_start", "window_end"}

PARAM_GRID = {
    "n_estimators": [100, 200],
    "max_samples": ["auto", 256],
    "contamination": [0.01, 0.05, 0.1],
}


@dataclass(frozen=True)
class Params:
    n_estimators: int = 200
    max_samples: int | str = "auto"
    contamination: float = 0.05
    seed: int = SEED


@dataclass
class Model:
    pipeline: Pipeline
    feature_cols: list[str]
    score_lo: float
    score_hi: float
    params: Params


def feature_columns(df: pd.DataFrame) -> list[str]:
    """Toutes les colonnes numériques qui ne sont pas des métadonnées."""
    numeric = df.select_dtypes(include="number").columns
    return [c for c in numeric if c not in META_COLS]


def _build_pipeline(p: Params) -> Pipeline:
    return Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "forest",
                IsolationForest(
                    n_estimators=p.n_estimators,
                    max_samples=p.max_samples,
                    contamination=p.contamination,
                    random_state=p.seed,
                    n_jobs=1,
                ),
            ),
        ]
    )


def _raw_scores(pipeline: Pipeline, x: pd.DataFrame) -> np.ndarray:
    """Plus la valeur est grande, plus la fenêtre est anormale."""
    return -pipeline.score_samples(x)


def train(train_df: pd.DataFrame, params: Params | None = None) -> Model:
    p = params or Params()
    cols = feature_columns(train_df)
    normal = train_df[train_df[LABEL_COL] == 0]
    if normal.empty:
        raise ValueError("Aucune fenêtre normale dans le jeu d'entraînement.")
    x = normal[cols].fillna(0)
    pipe = _build_pipeline(p).fit(x)
    raw = _raw_scores(pipe, x)
    # 0 = niveau médian du normal ; 1 = au-delà du 99e centile du normal
    lo, hi = float(np.percentile(raw, 50)), float(np.percentile(raw, 99))
    if hi <= lo:
        hi = lo + 1e-9
    return Model(pipe, cols, lo, hi, p)


def score_windows(model: Model, df: pd.DataFrame) -> pd.Series:
    """Score d'anomalie normalisé dans [0, 1], un par fenêtre."""
    x = df[model.feature_cols].fillna(0)
    raw = _raw_scores(model.pipeline, x)
    norm = np.clip((raw - model.score_lo) / (model.score_hi - model.score_lo), 0, 1)
    return pd.Series(norm, index=df.index, name="ml_score")


def predict(model: Model, df: pd.DataFrame) -> pd.Series:
    """1 = anomalie, 0 = normal (seuil interne de l'Isolation Forest)."""
    x = df[model.feature_cols].fillna(0)
    pred = (model.pipeline.predict(x) == -1).astype(int)
    return pd.Series(pred, index=df.index, name="ml_pred")


def tune(train_df: pd.DataFrame, seed: int = SEED) -> Params:
    """Choisit les hyperparamètres sur une validation interne au jeu train.

    Le jeu de test n'est jamais utilisé ici (pas de fuite).
    """
    ids = train_df[IDENTITY_COL].drop_duplicates()
    tr_ids, val_ids = train_test_split(ids, test_size=0.25, random_state=seed)
    sub_train = train_df[train_df[IDENTITY_COL].isin(tr_ids)]
    val = train_df[train_df[IDENTITY_COL].isin(val_ids)]
    if val[LABEL_COL].nunique() < 2:
        return Params(seed=seed)

    best, best_f1 = Params(seed=seed), -1.0
    keys = list(PARAM_GRID)
    for values in itertools.product(*PARAM_GRID.values()):
        p = Params(**dict(zip(keys, values, strict=True)), seed=seed)
        model = train(sub_train, p)
        f1 = f1_score(val[LABEL_COL], predict(model, val), zero_division=0)
        if f1 > best_f1:
            best, best_f1 = p, f1
    return best


def save(model: Model, directory: Path = MODEL_DIR) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "isolation_forest.joblib"
    joblib.dump(model, path)
    meta = {
        "params": asdict(model.params),
        "n_features": len(model.feature_cols),
        "features": model.feature_cols,
    }
    (directory / "isolation_forest.json").write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return path


def load(directory: Path = MODEL_DIR) -> Model:
    return joblib.load(directory / "isolation_forest.joblib")


def _read(path: Path) -> pd.DataFrame:
    if path.suffix == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path)


def main() -> None:
    ap = argparse.ArgumentParser(description="Entraîne l'Isolation Forest.")
    ap.add_argument("--input", type=Path, required=True, help="features .csv/.parquet")
    ap.add_argument("--no-tune", action="store_true")
    args = ap.parse_args()

    df = _read(args.input)
    split = split_by_identity(df)
    params = Params() if args.no_tune else tune(split.train)
    model = train(split.train, params)
    path = save(model)

    test_pred = predict(model, split.test)
    f1 = f1_score(split.test[LABEL_COL], test_pred, zero_division=0)
    print(f"Paramètres : {params}")
    print(f"Modèle sauvegardé : {path}")
    print(f"F1 sur le test (indicatif, détail en S5) : {f1:.3f}")


if __name__ == "__main__":
    main()
