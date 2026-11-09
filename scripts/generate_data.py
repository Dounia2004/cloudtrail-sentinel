"""Générateur de logs CloudTrail synthétiques (version 1).

Produit deux fichiers dans le dossier de sortie :
  - cloudtrail_logs.json : les événements, au format CloudTrail ({"Records": [...]})
  - labels.csv           : pour chaque événement, son scénario et s'il s'agit d'une attaque

Toutes les valeurs sont fictives : compte 123456789012, IP de documentation (RFC 5737).
Bibliothèque standard uniquement : aucune installation nécessaire.
"""
import argparse
import csv
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"

# Utilisateurs légitimes : (nom, IP habituelle, outil habituel)
USERS = [
    ("alice", "203.0.113.10", "aws-cli/2.15.0"),
    ("bob", "203.0.113.11", "aws-cli/2.15.0"),
    ("carol", "203.0.113.12", "console.amazonaws.com"),
    ("dave", "203.0.113.13", "Boto3/1.34.0"),
]

# Actions courantes de l'activité normale : (service, action)
NORMAL_ACTIONS = [
    ("s3.amazonaws.com", "ListBuckets"),
    ("s3.amazonaws.com", "GetObject"),
    ("ec2.amazonaws.com", "DescribeInstances"),
    ("cloudwatch.amazonaws.com", "DescribeAlarms"),
    ("s3.amazonaws.com", "PutObject"),
]

ATTACKER_IP = "198.51.100.77"  # IP jamais vue, utilisée par l'attaquant


def new_event_id(rng):
    """Identifiant unique, reproductible grâce à la graine aléatoire."""
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def make_event(rng, when, user, source, name, ip, agent, params=None,
               mfa=None, login=None, error_code=None):
    """Construit un événement au format CloudTrail."""
    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{user}",
            "accountId": ACCOUNT_ID,
            "userName": user,
        },
        "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": source,
        "eventName": name,
        "awsRegion": REGION,
        "sourceIPAddress": ip,
        "userAgent": agent,
        "requestParameters": params,
        "responseElements": None,
        "eventID": new_event_id(rng),
        "eventType": "AwsApiCall",
    }
    if error_code:
        event["errorCode"] = error_code
    if name == "ConsoleLogin":
        event["eventType"] = "AwsConsoleSignIn"
        event["responseElements"] = {"ConsoleLogin": login or "Success"}
        event["additionalEventData"] = {"MFAUsed": "Yes" if mfa else "No"}
    return event


def normal_activity(rng, start, days):
    """Activité normale : chaque utilisateur travaille aux heures de bureau, depuis son IP."""
    rows = []
    for day in range(days):
        base = start + timedelta(days=day)
        for user, ip, agent in USERS:
            login_time = base.replace(hour=rng.randint(8, 9), minute=rng.randint(0, 59))
            rows.append((make_event(rng, login_time, user, "signin.amazonaws.com",
                                    "ConsoleLogin", ip, agent, mfa=True), "normal", 0))
            for _ in range(rng.randint(5, 12)):
                when = base.replace(hour=rng.randint(9, 17), minute=rng.randint(0, 59),
                                    second=rng.randint(0, 59))
                source, name = rng.choice(NORMAL_ACTIONS)
                rows.append((make_event(rng, when, user, source, name, ip, agent), "normal", 0))
    return rows


def privilege_escalation(rng, when):
    """Scénario : bob (compte compromis) crée un utilisateur et lui donne les droits admin."""
    ip, agent = ATTACKER_IP, "aws-cli/2.15.0"
    steps = [
        (when, "bob", "iam.amazonaws.com", "CreateUser",
         {"userName": "svc-backup"}, None),
        (when + timedelta(minutes=1), "bob", "iam.amazonaws.com", "AttachUserPolicy",
         {"userName": "svc-backup",
          "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, None),
        (when + timedelta(minutes=3), "svc-backup", "signin.amazonaws.com", "ConsoleLogin",
         None, False),
    ]
    rows = []
    for t, user, source, name, params, mfa in steps:
        event = make_event(rng, t, user, source, name, ip, agent, params=params, mfa=mfa)
        rows.append((event, "privilege_escalation", 1))
    return rows


def main():
    parser = argparse.ArgumentParser(description="Génère des logs CloudTrail synthétiques")
    parser.add_argument("--days", type=int, default=3, help="nombre de jours d'activité normale")
    parser.add_argument("--seed", type=int, default=42, help="graine aléatoire (reproductibilité)")
    parser.add_argument("--out", default="data/generated", help="dossier de sortie")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    start = datetime(2026, 11, 10, tzinfo=timezone.utc)

    rows = normal_activity(rng, start, args.days)
    attack_time = start + timedelta(days=args.days - 1, hours=10, minutes=24)
    rows += privilege_escalation(rng, attack_time)
    rows.sort(key=lambda r: r[0]["eventTime"])

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "cloudtrail_logs.json", "w", encoding="utf-8") as f:
        json.dump({"Records": [r[0] for r in rows]}, f, indent=2)
    with open(out / "labels.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["eventID", "scenario", "is_attack"])
        for event, scenario, is_attack in rows:
            writer.writerow([event["eventID"], scenario, is_attack])

    attacks = sum(r[2] for r in rows)
    print(f"{len(rows)} événements générés ({attacks} d'attaque) dans {out}/")


if __name__ == "__main__":
    main()
