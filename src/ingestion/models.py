"""Modèles Pydantic : validation des événements CloudTrail et normalisation.

Chaîne de traitement :
  fichier JSON CloudTrail -> CloudTrailRecord (validation) -> Event (table `events`)

Les noms des champs de `Event` suivent docs/contracts.md.
"""
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError


class UserIdentity(BaseModel):
    """Qui a fait l'action (bloc `userIdentity` de CloudTrail)."""

    model_config = ConfigDict(extra="allow")

    type: str
    arn: str | None = None
    accountId: str | None = None
    userName: str | None = None


class CloudTrailRecord(BaseModel):
    """Un événement CloudTrail brut. Un champ obligatoire manquant provoque un rejet."""

    model_config = ConfigDict(extra="allow")

    eventVersion: str
    userIdentity: UserIdentity
    eventTime: datetime
    eventSource: str
    eventName: str
    awsRegion: str
    sourceIPAddress: str
    userAgent: str | None = None
    requestParameters: dict[str, Any] | None = None
    responseElements: dict[str, Any] | None = None
    additionalEventData: dict[str, Any] | None = None
    errorCode: str | None = None
    eventID: str
    eventType: str


class Event(BaseModel):
    """Un événement normalisé : une ligne de la table `events`."""

    event_id: str
    event_time: str
    event_source: str
    event_name: str
    aws_region: str
    identity_type: str
    identity_name: str
    identity_arn: str | None = None
    source_ip: str
    user_agent: str | None = None
    mfa_used: int | None = None
    error_code: str | None = None
    login_result: str | None = None
    request_params: str | None = None
    scenario: str = "unknown"
    is_attack: int = 0


def _identity_name(identity: UserIdentity) -> str:
    """Nom de l'identité : clé de corrélation du projet."""
    if identity.userName:
        return identity.userName
    if identity.arn:
        return identity.arn.split("/")[-1]
    return identity.type


def _mfa_used(record: CloudTrailRecord) -> int | None:
    """1 si MFA utilisé, 0 sinon, None si l'information n'existe pas."""
    value = (record.additionalEventData or {}).get("MFAUsed")
    if value == "Yes":
        return 1
    if value == "No":
        return 0
    return None


def normalize(record: CloudTrailRecord, scenario: str = "unknown", is_attack: int = 0) -> Event:
    """Transforme un événement CloudTrail validé en ligne de la table `events`."""
    when = record.eventTime
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    when = when.astimezone(timezone.utc)

    login_result = None
    if record.eventName == "ConsoleLogin" and record.responseElements:
        login_result = record.responseElements.get("ConsoleLogin")

    params = None
    if record.requestParameters is not None:
        params = json.dumps(record.requestParameters, sort_keys=True)

    return Event(
        event_id=record.eventID,
        event_time=when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        event_source=record.eventSource,
        event_name=record.eventName,
        aws_region=record.awsRegion,
        identity_type=record.userIdentity.type,
        identity_name=_identity_name(record.userIdentity),
        identity_arn=record.userIdentity.arn,
        source_ip=record.sourceIPAddress,
        user_agent=record.userAgent,
        mfa_used=_mfa_used(record),
        error_code=record.errorCode,
        login_result=login_result,
        request_params=params,
        scenario=scenario,
        is_attack=is_attack,
    )


def load_labels(path: str | Path) -> dict[str, tuple[str, int]]:
    """Lit labels.csv : eventID -> (scénario, is_attack)."""
    labels = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            labels[row["eventID"]] = (row["scenario"], int(row["is_attack"]))
    return labels


def load_events(logs_path: str | Path, labels_path: str | Path | None = None):
    """Lit un fichier CloudTrail, valide chaque événement et retourne (événements, rejets)."""
    labels = load_labels(labels_path) if labels_path else {}
    with open(logs_path, encoding="utf-8") as f:
        raw = json.load(f)

    events, rejected = [], []
    for item in raw.get("Records", []):
        try:
            record = CloudTrailRecord.model_validate(item)
        except ValidationError as err:
            first = err.errors()[0]
            where = ".".join(str(x) for x in first["loc"])
            reason = f"{where}: {first['msg']}"
            rejected.append({"eventID": item.get("eventID", "?"), "error": reason})
            continue
        scenario, is_attack = labels.get(record.eventID, ("unknown", 0))
        events.append(normalize(record, scenario, is_attack))
    return events, rejected


if __name__ == "__main__":
    events, rejected = load_events(
        "data/generated/cloudtrail_logs.json", "data/generated/labels.csv"
    )
    print(f"{len(events)} événements valides, {len(rejected)} rejetés")
    print(f"dont {sum(e.is_attack for e in events)} d'attaque")
