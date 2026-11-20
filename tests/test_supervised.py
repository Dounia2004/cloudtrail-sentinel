import numpy as np
import pandas as pd
import pytest

from src.detection.ml.features import FEATURE_COLUMNS
from src.detection.ml.split import IDENTITY_COL, LABEL_COL, SCENARIO_COL
from src.detection.ml.supervised import (
    predict_supervised,
    score_supervised,
    train_supervised,
)


def _df(seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(80):
        row = {c: float(rng.poisson(3)) for c in FEATURE_COLUMNS}
        row.update({IDENTITY_COL: f"user{i}", SCENARIO_COL: "normal", LABEL_COL: 0})
        rows.append(row)
    for i in range(10):
        row = {c: float(rng.poisson(3)) for c in FEATURE_COLUMNS}
        row["n_iam_write"] = float(rng.poisson(30))
        row.update({IDENTITY_COL: f"atk{i}", SCENARIO_COL: "iam_recon", LABEL_COL: 1})
        rows.append(row)
    return pd.DataFrame(rows)


def test_scores_between_0_and_1():
    df = _df()
    s = score_supervised(train_supervised(df), df)
    assert s.between(0, 1).all()


def test_attacks_score_higher():
    df = _df()
    s = score_supervised(train_supervised(df), df)
    assert s[df[LABEL_COL] == 1].mean() > s[df[LABEL_COL] == 0].mean()


def test_reproducible():
    df = _df()
    a = score_supervised(train_supervised(df, seed=42), df)
    b = score_supervised(train_supervised(df, seed=42), df)
    assert np.allclose(a, b)


def test_predict_is_binary():
    df = _df()
    pred = predict_supervised(train_supervised(df), df)
    assert set(pred.unique()) <= {0, 1}


def test_needs_both_classes():
    df = _df()
    with pytest.raises(ValueError):
        train_supervised(df[df[LABEL_COL] == 0])
