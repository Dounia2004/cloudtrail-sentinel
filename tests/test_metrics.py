import pandas as pd
import pytest

from src.evaluation.metrics import (
    by_scenario,
    compute_metrics,
    confusion_matrix,
    evaluate_models,
    to_markdown,
)


def test_known_values():
    y = pd.Series([1, 1, 1, 0, 0, 0, 0, 0])
    p = pd.Series([1, 1, 0, 1, 0, 0, 0, 0])
    m = compute_metrics(y, p)
    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (2, 1, 4, 1)
    assert m["precision"] == pytest.approx(2 / 3)
    assert m["recall"] == pytest.approx(2 / 3)
    assert m["f1"] == pytest.approx(2 / 3)
    assert m["fpr"] == pytest.approx(1 / 5)


def test_no_prediction_gives_zero_not_error():
    m = compute_metrics(pd.Series([1, 0]), pd.Series([0, 0]))
    assert m["precision"] == 0.0 and m["recall"] == 0.0 and m["f1"] == 0.0


def test_length_mismatch_raises():
    with pytest.raises(ValueError):
        compute_metrics(pd.Series([1, 0]), pd.Series([1]))


def test_confusion_matrix_layout():
    m = compute_metrics(pd.Series([1, 0, 0]), pd.Series([1, 1, 0]))
    cm = confusion_matrix(m)
    assert cm.loc["réel : attaque", "prédit : attaque"] == 1
    assert cm.loc["réel : normal", "prédit : attaque"] == 1


def _test_df():
    return pd.DataFrame(
        {
            "is_attack": [1, 1, 0, 0, 0],
            "scenario": ["iam_recon", "iam_recon", "normal", "normal", "benign_vpn_login"],
        }
    )


def test_evaluate_models_and_by_scenario():
    df = _test_df()
    preds = {"regles": pd.Series([1, 0, 0, 1, 0], index=df.index)}
    ev = evaluate_models(df, preds)
    assert ev.loc[0, "modèle"] == "regles"
    assert ev.loc[0, "tp"] == 1
    sc = by_scenario(df, preds).set_index("scénario")
    assert sc.loc["iam_recon", "regles"] == 0.5
    assert sc.loc["normal", "regles"] == 0.5
    assert sc.loc["benign_vpn_login", "type"] == "normal"


def test_markdown_has_header_and_rows():
    md = to_markdown(pd.DataFrame({"a": [1], "b": [0.5]}))
    lines = md.splitlines()
    assert lines[0] == "| a | b |" and len(lines) == 3
