import numpy as np
import pandas as pd
import pytest

from src.detection.ml.features import FEATURE_COLUMNS
from src.detection.ml.split import IDENTITY_COL, LABEL_COL, SCENARIO_COL
from src.detection.ml.train import (
    Params,
    feature_columns,
    load,
    predict,
    save,
    score_windows,
    train,
)


def _df(seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(80):
        row = {c: float(rng.poisson(3)) for c in FEATURE_COLUMNS}
        row["error_rate"] = rng.uniform(0, 0.1)
        row.update({IDENTITY_COL: f"user{i}", SCENARIO_COL: "normal", LABEL_COL: 0})
        rows.append(row)
    for i in range(10):
        row = {c: float(rng.poisson(3)) for c in FEATURE_COLUMNS}
        row["n_iam_write"] = float(rng.poisson(30))
        row["error_rate"] = rng.uniform(0.5, 0.9)
        row.update(
            {IDENTITY_COL: f"atk{i}", SCENARIO_COL: "privilege_escalation", LABEL_COL: 1}
        )
        rows.append(row)
    return pd.DataFrame(rows)


def test_feature_columns_excludes_labels():
    cols = feature_columns(_df())
    assert cols == list(FEATURE_COLUMNS)
    assert not {"is_attack", "scenario", "n_attack_events", "identity"} & set(cols)


def test_scores_between_0_and_1():
    df = _df()
    s = score_windows(train(df), df)
    assert s.between(0, 1).all()


def test_attacks_score_higher_than_normal():
    df = _df()
    s = score_windows(train(df), df)
    assert s[df[LABEL_COL] == 1].mean() > s[df[LABEL_COL] == 0].mean()


def test_reproducible_with_same_seed():
    df = _df()
    a = score_windows(train(df, Params(seed=42)), df)
    b = score_windows(train(df, Params(seed=42)), df)
    assert np.allclose(a, b)


def test_predict_is_binary():
    df = _df()
    pred = predict(train(df), df)
    assert set(pred.unique()) <= {0, 1}


def test_train_requires_normal_rows():
    df = _df()
    with pytest.raises(ValueError):
        train(df[df[LABEL_COL] == 1])


def test_save_and_load_roundtrip(tmp_path):
    df = _df()
    model = train(df)
    save(model, tmp_path)
    loaded = load(tmp_path)
    assert np.allclose(score_windows(model, df), score_windows(loaded, df))
