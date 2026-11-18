"""Features pour le machine learning : une ligne par identité et par fenêtre de temps.

Pour chaque identité et chaque fenêtre (une heure par défaut), on résume l'activité en
quelques nombres : combien d'appels, de quel type, depuis combien d'IP, avec quelles erreurs.
C'est ce tableau que l'Isolation Forest lira à l'étape suivante.

Les colonnes d'étiquette (is_attack, scenario, n_attack_events) servent uniquement à
l'évaluation : elles ne doivent jamais faire partie des features données au modèle.

Utilisation (depuis la racine du projet) :
    python -m src.detection.ml.features
    python -m src.detection.ml.features --out data/generated_ml/features.csv
"""
import argparse
from pathlib import Path

import pandas as pd

from src.ingestion.models import Event, load_events

IAM_SOURCE = "iam.amazonaws.com"
IAM_WRITE_PREFIXES = ("Create", "Attach", "Put", "Update", "Delete", "Add", "Detach", "Remove")
S3_READ_EVENTS = {"GetObject", "ListBucket", "ListObjects", "ListObjectsV2", "ListBuckets"}

KEY_COLUMNS = ["identity", "window_start"]
FEATURE_COLUMNS = [
    "n_events",  # nombre d'appels dans la fenêtre
    "n_event_types",  # nombre de types d'appels différents
    "n_services",  # nombre de services AWS différents
    "n_iam_read",  # lectures IAM (List*, Get*)
    "n_iam_write",  # modifications IAM (Create*, Attach*, Put*, ...)
    "n_s3_read",  # lectures S3
    "n_login_failures",  # échecs de connexion
    "n_login_no_mfa",  # connexions réussies sans MFA
    "n_errors",  # appels en erreur
    "error_rate",  # part des appels en erreur
    "n_distinct_ips",  # nombre d'IP différentes
    "n_new_ips",  # IP jamais vues avant pour cette identité
    "n_distinct_regions",  # nombre de régions différentes
    "n_off_region_events",  # appels hors de la région habituelle de l'identité
    "hour",  # heure de la fenêtre (UTC)
    "is_weekend",  # 1 si samedi ou dimanche
]
LABEL_COLUMNS = ["is_attack", "scenario", "n_attack_events"]


def events_to_frame(events: list[Event]) -> pd.DataFrame:
    """Convertit des événements normalisés en tableau pandas."""
    return pd.DataFrame([event.model_dump() for event in events])


def _empty() -> pd.DataFrame:
    return pd.DataFrame(columns=KEY_COLUMNS + FEATURE_COLUMNS + LABEL_COLUMNS)


def build_features(events: list[Event], window: str = "1h") -> pd.DataFrame:
    """Une ligne par (identité, fenêtre de temps) avec les features et les étiquettes."""
    if not events:
        return _empty()
    df = events_to_frame(events)
    df["time"] = pd.to_datetime(df["event_time"], utc=True)
    df = df.sort_values(["time", "event_id"], kind="stable").reset_index(drop=True)
    df["window_start"] = df["time"].dt.floor(window)

    # Indicateurs par événement (1 ou 0), additionnés ensuite par fenêtre.
    is_iam = df["event_source"].eq(IAM_SOURCE)
    is_login = df["event_name"].eq("ConsoleLogin")
    df["is_iam_read"] = (is_iam & df["event_name"].str.startswith(("List", "Get"))).astype(int)
    df["is_iam_write"] = (is_iam & df["event_name"].str.startswith(IAM_WRITE_PREFIXES)).astype(int)
    df["is_s3_read"] = df["event_name"].isin(S3_READ_EVENTS).astype(int)
    df["is_login_failure"] = (is_login & df["login_result"].eq("Failure")).astype(int)
    no_mfa = is_login & df["login_result"].eq("Success") & df["mfa_used"].eq(0)
    df["is_login_no_mfa"] = no_mfa.astype(int)
    df["is_error"] = df["error_code"].notna().astype(int)

    # Nouvelle IP : première apparition de l'IP pour l'identité, alors qu'elle a déjà un historique.
    first_time = df.groupby("identity_name")["time"].transform("min")
    has_history = first_time.dt.floor(window) < df["window_start"]
    first_use = df.groupby(["identity_name", "source_ip"]).cumcount() == 0
    df["is_new_ip"] = (first_use & has_history).astype(int)

    # Région habituelle de l'identité : la plus fréquente sur l'ensemble des données.
    home = df.groupby("identity_name")["aws_region"].agg(lambda s: s.mode().iloc[0])
    df["is_off_region"] = (df["aws_region"] != df["identity_name"].map(home)).astype(int)

    grouped = df.groupby(["identity_name", "window_start"])
    features = grouped.agg(
        n_events=("event_id", "size"),
        n_event_types=("event_name", "nunique"),
        n_services=("event_source", "nunique"),
        n_iam_read=("is_iam_read", "sum"),
        n_iam_write=("is_iam_write", "sum"),
        n_s3_read=("is_s3_read", "sum"),
        n_login_failures=("is_login_failure", "sum"),
        n_login_no_mfa=("is_login_no_mfa", "sum"),
        n_errors=("is_error", "sum"),
        n_distinct_ips=("source_ip", "nunique"),
        n_new_ips=("is_new_ip", "sum"),
        n_distinct_regions=("aws_region", "nunique"),
        n_off_region_events=("is_off_region", "sum"),
        n_attack_events=("is_attack", "sum"),
    ).reset_index()
    features = features.rename(columns={"identity_name": "identity"})
    features["error_rate"] = features["n_errors"] / features["n_events"]
    features["hour"] = features["window_start"].dt.hour
    features["is_weekend"] = (features["window_start"].dt.dayofweek >= 5).astype(int)
    features["is_attack"] = (features["n_attack_events"] > 0).astype(int)

    # Scénario dominant de la fenêtre : attaque d'abord, sinon anomalie bénigne, sinon normal.
    keys = ["identity_name", "window_start"]

    def dominant(part: pd.DataFrame) -> dict:
        return part.groupby(keys)["scenario"].agg(lambda s: s.mode().iloc[0]).to_dict()

    attack = dominant(df[df["is_attack"] == 1])
    benign = dominant(df[df["scenario"].str.startswith("benign_")])
    pairs = zip(features["identity"], features["window_start"], strict=True)
    features["scenario"] = [attack.get(k, benign.get(k, "normal")) for k in pairs]

    return features[KEY_COLUMNS + FEATURE_COLUMNS + LABEL_COLUMNS]


def main() -> None:
    parser = argparse.ArgumentParser(description="Calcule les features par identité et fenêtre")
    parser.add_argument("--logs", default="data/generated_ml/cloudtrail_logs.json")
    parser.add_argument("--labels", default="data/generated_ml/labels.csv")
    parser.add_argument("--window", default="1h", help="taille de la fenêtre (ex. 1h, 30min)")
    parser.add_argument("--out", default=None, help="écrit aussi les features en CSV")
    args = parser.parse_args()

    events, _ = load_events(args.logs, args.labels)
    features = build_features(events, args.window)

    print(f"{len(events)} événements -> {len(features)} fenêtres ({args.window}) "
          f"pour {features['identity'].nunique()} identités")
    print(f"fenêtres d'attaque : {int(features['is_attack'].sum())}")
    print()
    print(features["scenario"].value_counts().to_string())
    print()
    summary = ["n_events", "n_iam_write", "n_s3_read", "n_errors", "n_new_ips",
               "n_off_region_events"]
    print("Moyenne de quelques features (0 = fenêtres sans attaque, 1 = avec attaque) :")
    print(features.groupby("is_attack")[summary].mean().round(2).to_string())
    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        features.to_csv(path, index=False)
        print(f"\nFeatures écrites dans {path}")


if __name__ == "__main__":
    main()
