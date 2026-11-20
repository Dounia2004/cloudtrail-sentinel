import pandas as pd
import pytest

from src.detection.ml.split import (
    IDENTITY_COL,
    LABEL_COL,
    SCENARIO_COL,
    split_by_identity,
)


def _df():
    rows = []
    for i in range(40):
        rows.append({IDENTITY_COL: f"user{i}", SCENARIO_COL: "normal", LABEL_COL: 0})
    for i in range(10):
        rows.append(
            {IDENTITY_COL: f"atk{i}", SCENARIO_COL: "privilege_escalation", LABEL_COL: 1}
        )
    for i in range(5):
        rows.append(
            {IDENTITY_COL: f"key{i}", SCENARIO_COL: "access_key_persistence", LABEL_COL: 1}
        )
    return pd.DataFrame(rows)


def test_no_identity_overlap():
    s = split_by_identity(_df())
    assert set(s.train[IDENTITY_COL]).isdisjoint(s.test[IDENTITY_COL])


def test_unseen_scenario_only_in_test():
    s = split_by_identity(_df())
    assert "access_key_persistence" not in set(s.train[SCENARIO_COL])
    assert "access_key_persistence" in set(s.test[SCENARIO_COL])


def test_reproducible():
    a, b = split_by_identity(_df()), split_by_identity(_df())
    assert a.train.equals(b.train) and a.test.equals(b.test)


def test_missing_scenario_raises():
    with pytest.raises(ValueError):
        split_by_identity(_df(), unseen_scenario="inexistant")
