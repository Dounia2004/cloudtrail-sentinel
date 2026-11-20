from dataclasses import dataclass

import pandas as pd

from src.evaluation.compare import (
    alerts_by_rule,
    alerts_to_windows,
    combine,
)


@dataclass
class FakeAlert:
    identity: str
    rule_id: str
    first_seen: str
    last_seen: str


def _windows() -> pd.DataFrame:
    hours = pd.date_range("2026-11-10 09:00", periods=4, freq="1h", tz="UTC")
    rows = []
    for ident in ("alice", "bob"):
        for i, h in enumerate(hours):
            rows.append(
                {
                    "identity": ident,
                    "window_start": h,
                    "is_attack": int(ident == "alice" and i == 1),
                }
            )
    return pd.DataFrame(rows)


def test_alert_flags_only_its_window_and_identity():
    w = _windows()
    alert = FakeAlert("alice", "IAM-001", "2026-11-10T10:24:00Z", "2026-11-10T10:27:00Z")
    flags = alerts_to_windows([alert], w)
    assert flags.sum() == 1
    row = w[flags == 1].iloc[0]
    assert row["identity"] == "alice" and row["window_start"].hour == 10


def test_alert_spanning_hours_flags_each_window():
    w = _windows()
    alert = FakeAlert("bob", "AUTH-001", "2026-11-10T09:50:00Z", "2026-11-10T11:05:00Z")
    flags = alerts_to_windows([alert], w)
    assert flags.sum() == 3
    assert set(w[flags == 1]["identity"]) == {"bob"}


def test_string_window_start_is_supported():
    w = _windows()
    w["window_start"] = w["window_start"].astype(str)
    alert = {
        "identity": "alice",
        "rule_id": "IAM-001",
        "first_seen": "2026-11-10T10:00:00Z",
        "last_seen": "2026-11-10T10:30:00Z",
    }
    assert alerts_to_windows([alert], w).sum() == 1


def test_no_alert_means_no_flag():
    assert alerts_to_windows([], _windows()).sum() == 0


def test_combine_is_or():
    r = pd.Series([1, 0, 0, 1])
    m = pd.Series([0, 1, 0, 1])
    assert combine(r, m).tolist() == [1, 1, 0, 1]


def test_alerts_by_rule_counts_true_and_false_positives():
    w = _windows()
    good = FakeAlert("alice", "IAM-001", "2026-11-10T10:10:00Z", "2026-11-10T10:20:00Z")
    bad = FakeAlert("bob", "IAM-001", "2026-11-10T09:10:00Z", "2026-11-10T09:20:00Z")
    table = alerts_by_rule([good, bad], w).set_index("règle")
    assert table.loc["IAM-001", "alertes"] == 2
    assert table.loc["IAM-001", "sur_attaque"] == 1
    assert table.loc["IAM-001", "sur_normal"] == 1
