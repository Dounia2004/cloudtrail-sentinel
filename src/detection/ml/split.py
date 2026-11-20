"""Séparation train/test par identité, avec un scénario d'attaque jamais vu à l'entraînement."""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
from sklearn.model_selection import train_test_split

SEED = 42
IDENTITY_COL = "identity"
LABEL_COL = "is_attack"        # 0 = normal, 1 = attaque
SCENARIO_COL = "scenario"
UNSEEN_SCENARIO = "access_key_persistence"


@dataclass(frozen=True)
class Split:
    train: pd.DataFrame
    test: pd.DataFrame
    unseen_scenario: str


def split_by_identity(
    df: pd.DataFrame,
    unseen_scenario: str = UNSEEN_SCENARIO,
    test_size: float = 0.3,
    seed: int = SEED,
) -> Split:
    """Aucune identité n'apparaît à la fois dans train et test.

    - Toutes les identités touchées par `unseen_scenario` vont dans le test.
    - Les autres identités sont réparties 70/30, stratifiées (attaque / pas d'attaque).
    """
    unseen_ids = set(df.loc[df[SCENARIO_COL] == unseen_scenario, IDENTITY_COL])
    if not unseen_ids:
        available = sorted(df[SCENARIO_COL].unique())
        raise ValueError(
            f"Scénario '{unseen_scenario}' absent des données. Disponibles : {available}"
        )

    rest = df[~df[IDENTITY_COL].isin(unseen_ids)]
    ids = (
        rest.groupby(IDENTITY_COL)[LABEL_COL].max().rename("has_attack").reset_index()
    )
    counts = ids["has_attack"].value_counts()
    stratify = ids["has_attack"] if len(counts) > 1 and counts.min() >= 2 else None

    train_ids, test_ids = train_test_split(
        ids[IDENTITY_COL], test_size=test_size, random_state=seed, stratify=stratify
    )

    train = rest[rest[IDENTITY_COL].isin(train_ids)]
    test = pd.concat(
        [rest[rest[IDENTITY_COL].isin(test_ids)], df[df[IDENTITY_COL].isin(unseen_ids)]]
    )

    assert set(train[IDENTITY_COL]).isdisjoint(test[IDENTITY_COL])
    assert unseen_scenario not in set(train[SCENARIO_COL])

    return Split(
        train.sort_index().reset_index(drop=True),
        test.sort_index().reset_index(drop=True),
        unseen_scenario,
    )


def summary(split: Split) -> pd.DataFrame:
    """Tableau récapitulatif (à copier dans le rapport)."""
    rows = []
    for name, part in (("train", split.train), ("test", split.test)):
        for scen, n in part[SCENARIO_COL].value_counts().items():
            rows.append({"jeu": name, "scénario": scen, "fenêtres": n})
    return pd.DataFrame(rows)
