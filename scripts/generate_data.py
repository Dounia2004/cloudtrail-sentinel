"""Générateur de logs CloudTrail synthétiques (version 2).

Produit deux fichiers dans le dossier de sortie :
  - cloudtrail_logs.json : les événements, au format CloudTrail ({"Records": [...]})
  - labels.csv           : pour chaque événement, son scénario et s'il s'agit d'une attaque

Scénarios : activité normale + 7 scénarios d'attaque
  privilege_escalation, credential_abuse, iam_recon, defense_evasion,
  s3_exfiltration, no_mfa_login, persistence_access_key

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
BUCKET = "example-bucket-confidential"

# Utilisateurs légitimes : nom -> (IP habituelle, outil habituel)
USERS = {
    "alice": ("203.0.113.10", "aws-cli/2.15.0"),
    "bob": ("203.0.113.11", "aws-cli/2.15.0"),
    "carol": ("203.0.113.12", "console.amazonaws.com"),
    "dave": ("203.0.113.13", "Boto3/1.34.0"),
}

# Actions courantes de l'activité normale : (service, action)
NORMAL_ACTIONS = [
    ("s3.amazonaws.com", "ListBuckets"),
    ("s3.amazonaws.com", "GetObject"),
    ("ec2.amazonaws.com", "DescribeInstances"),
    ("cloudwatch.amazonaws.com", "DescribeAlarms"),
    ("s3.amazonaws.com", "PutObject"),
]

ATTACKER_AGENT = "aws-cli/2.15.0"


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
        for user, (ip, agent) in USERS.items():
            login_time = base.replace(hour=rng.randint(8, 9), minute=rng.randint(0, 59))
            rows.append((make_event(rng, login_time, user, "signin.amazonaws.com",
                                    "ConsoleLogin", ip, agent, mfa=True), "normal", 0))
            for _ in range(rng.randint(5, 12)):
                when = base.replace(hour=rng.randint(9, 17), minute=rng.randint(0, 59),
                                    second=rng.randint(0, 59))
                source, name = rng.choice(NORMAL_ACTIONS)
                rows.append((make_event(rng, when, user, source, name, ip, agent), "normal", 0))
    return rows


def attack_rows(events, scenario):
    """Associe chaque événement d'attaque à son scénario (is_attack = 1)."""
    return [(event, scenario, 1) for event in events]


def privilege_escalation(rng, when):
    """bob (compte compromis) crée un utilisateur et lui donne les droits admin."""
    ip = "198.51.100.77"
    events = [
        make_event(rng, when, "bob", "iam.amazonaws.com", "CreateUser", ip, ATTACKER_AGENT,
                   params={"userName": "svc-backup"}),
        make_event(rng, when + timedelta(minutes=1), "bob", "iam.amazonaws.com",
                   "AttachUserPolicy", ip, ATTACKER_AGENT,
                   params={"userName": "svc-backup",
                           "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
        make_event(rng, when + timedelta(minutes=3), "svc-backup", "signin.amazonaws.com",
                   "ConsoleLogin", ip, ATTACKER_AGENT, mfa=False),
    ]
    return attack_rows(events, "privilege_escalation")


def credential_abuse(rng, when):
    """Plusieurs échecs de connexion sur carol, puis un succès sans MFA depuis une IP inconnue."""
    ip = "198.51.100.88"
    events = []
    for i in range(6):
        events.append(make_event(rng, when + timedelta(seconds=40 * i), "carol",
                                 "signin.amazonaws.com", "ConsoleLogin", ip, ATTACKER_AGENT,
                                 mfa=False, login="Failure"))
    events.append(make_event(rng, when + timedelta(minutes=5), "carol", "signin.amazonaws.com",
                             "ConsoleLogin", ip, ATTACKER_AGENT, mfa=False, login="Success"))
    return attack_rows(events, "credential_abuse")


def iam_recon(rng, when):
    """dave (compte compromis) explore le compte IAM en rafale."""
    ip = "198.51.100.99"
    calls = ["ListUsers", "ListRoles", "ListPolicies", "ListGroups",
             "ListAccessKeys", "ListAttachedUserPolicies", "GetAccountSummary",
             "GetAccountAuthorizationDetails"]
    events = [make_event(rng, when + timedelta(seconds=20 * i), "dave", "iam.amazonaws.com",
                         name, ip, ATTACKER_AGENT) for i, name in enumerate(calls)]
    return attack_rows(events, "iam_recon")


def defense_evasion(rng, when):
    """alice (compte compromis) arrête puis supprime la journalisation CloudTrail."""
    ip = "198.51.100.66"
    params = {"name": "management-events"}
    events = [
        make_event(rng, when, "alice", "cloudtrail.amazonaws.com", "StopLogging", ip,
                   ATTACKER_AGENT, params=params),
        make_event(rng, when + timedelta(minutes=2), "alice", "cloudtrail.amazonaws.com",
                   "DeleteTrail", ip, ATTACKER_AGENT, params=params),
    ]
    return attack_rows(events, "defense_evasion")


def s3_exfiltration(rng, when):
    """carol (compte compromis) liste les buckets puis télécharge 40 fichiers en 8 minutes."""
    ip = "198.51.100.55"
    events = [make_event(rng, when, "carol", "s3.amazonaws.com", "ListBuckets", ip,
                         ATTACKER_AGENT)]
    for i in range(40):
        events.append(make_event(rng, when + timedelta(seconds=12 * (i + 1)), "carol",
                                 "s3.amazonaws.com", "GetObject", ip, ATTACKER_AGENT,
                                 params={"bucketName": BUCKET, "key": f"export/file-{i:03d}.csv"}))
    return attack_rows(events, "s3_exfiltration")


def no_mfa_login(rng, when):
    """dave se connecte à la console sans MFA, depuis son IP habituelle."""
    ip, agent = USERS["dave"]
    events = [make_event(rng, when, "dave", "signin.amazonaws.com", "ConsoleLogin", ip, agent,
                         mfa=False, login="Success")]
    return attack_rows(events, "no_mfa_login")


def persistence_access_key(rng, when):
    """carol (compte compromis) crée une clé d'accès et un mot de passe pour alice."""
    ip = "198.51.100.44"
    params = {"userName": "alice"}
    events = [
        make_event(rng, when, "carol", "iam.amazonaws.com", "CreateAccessKey", ip,
                   ATTACKER_AGENT, params=params),
        make_event(rng, when + timedelta(minutes=1), "carol", "iam.amazonaws.com",
                   "CreateLoginProfile", ip, ATTACKER_AGENT, params=params),
    ]
    return attack_rows(events, "persistence_access_key")


# (fonction, jour de l'attaque, heure, minute) : jours répartis, bornés par --days
SCENARIOS = [
    (credential_abuse, 1, 2, 15),
    (iam_recon, 2, 14, 5),
    (no_mfa_login, 2, 20, 12),
    (defense_evasion, 3, 3, 40),
    (s3_exfiltration, 3, 22, 10),
    (persistence_access_key, 4, 15, 30),
    (privilege_escalation, 4, 10, 24),
]


def main():
    parser = argparse.ArgumentParser(description="Génère des logs CloudTrail synthétiques")
    parser.add_argument("--days", type=int, default=5, help="nombre de jours d'activité normale")
    parser.add_argument("--seed", type=int, default=42, help="graine aléatoire (reproductibilité)")
    parser.add_argument("--out", default="data/generated", help="dossier de sortie")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    start = datetime(2026, 11, 10, tzinfo=timezone.utc)

    rows = normal_activity(rng, start, args.days)
    for scenario, day, hour, minute in SCENARIOS:
        when = start + timedelta(days=min(day, args.days - 1), hours=hour, minutes=minute)
        rows += scenario(rng, when)
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
