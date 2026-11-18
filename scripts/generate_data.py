"""Générateur de logs CloudTrail synthétiques (version 3).

Produit deux fichiers dans le dossier de sortie :
  - cloudtrail_logs.json : les événements, au format CloudTrail ({"Records": [...]})
  - labels.csv           : pour chaque événement, son scénario et s'il s'agit d'une attaque

Mode de base (par défaut) : activité normale + 7 scénarios d'attaque
  privilege_escalation, credential_abuse, iam_recon, defense_evasion,
  s3_exfiltration, no_mfa_login, persistence_access_key

Mode étendu (--extended) : jeu de données pour le machine learning
  - plus d'utilisateurs, plus de jours, des rôles (développeur, analyste, administrateur),
    des week-ends plus calmes et des horaires de travail variés ;
  - des anomalies bénignes (scenario "benign_*", is_attack = 0) : arrivée d'un employé,
    outil d'audit, sauvegarde de nuit, connexion depuis un VPN, fautes de frappe ;
  - chaque attaque répétée plusieurs fois sur des victimes différentes ;
  - un scénario supplémentaire, crypto_mining, qu'aucune règle ne vise.

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
               mfa=None, login=None, error_code=None, region=REGION):
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
        "awsRegion": region,
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


def privilege_escalation(rng, when, actor="bob", ip="198.51.100.77", new_user="svc-backup"):
    """Un compte compromis crée un utilisateur et lui donne les droits admin."""
    events = [
        make_event(rng, when, actor, "iam.amazonaws.com", "CreateUser", ip, ATTACKER_AGENT,
                   params={"userName": new_user}),
        make_event(rng, when + timedelta(minutes=1), actor, "iam.amazonaws.com",
                   "AttachUserPolicy", ip, ATTACKER_AGENT,
                   params={"userName": new_user,
                           "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
        make_event(rng, when + timedelta(minutes=3), new_user, "signin.amazonaws.com",
                   "ConsoleLogin", ip, ATTACKER_AGENT, mfa=False),
    ]
    return attack_rows(events, "privilege_escalation")


def credential_abuse(rng, when, victim="carol", ip="198.51.100.88"):
    """Des échecs de connexion sur un compte, puis un succès sans MFA depuis une IP inconnue."""
    events = []
    for i in range(6):
        events.append(make_event(rng, when + timedelta(seconds=40 * i), victim,
                                 "signin.amazonaws.com", "ConsoleLogin", ip, ATTACKER_AGENT,
                                 mfa=False, login="Failure"))
    events.append(make_event(rng, when + timedelta(minutes=5), victim, "signin.amazonaws.com",
                             "ConsoleLogin", ip, ATTACKER_AGENT, mfa=False, login="Success"))
    return attack_rows(events, "credential_abuse")


def iam_recon(rng, when, victim="dave", ip="198.51.100.99"):
    """Un compte compromis explore le compte IAM en rafale."""
    calls = ["ListUsers", "ListRoles", "ListPolicies", "ListGroups",
             "ListAccessKeys", "ListAttachedUserPolicies", "GetAccountSummary",
             "GetAccountAuthorizationDetails"]
    events = [make_event(rng, when + timedelta(seconds=20 * i), victim, "iam.amazonaws.com",
                         name, ip, ATTACKER_AGENT) for i, name in enumerate(calls)]
    return attack_rows(events, "iam_recon")


def defense_evasion(rng, when, victim="alice", ip="198.51.100.66"):
    """Un compte compromis arrête puis supprime la journalisation CloudTrail."""
    params = {"name": "management-events"}
    events = [
        make_event(rng, when, victim, "cloudtrail.amazonaws.com", "StopLogging", ip,
                   ATTACKER_AGENT, params=params),
        make_event(rng, when + timedelta(minutes=2), victim, "cloudtrail.amazonaws.com",
                   "DeleteTrail", ip, ATTACKER_AGENT, params=params),
    ]
    return attack_rows(events, "defense_evasion")


def s3_exfiltration(rng, when, victim="carol", ip="198.51.100.55"):
    """Un compte compromis liste les buckets puis télécharge 40 fichiers en 8 minutes."""
    events = [make_event(rng, when, victim, "s3.amazonaws.com", "ListBuckets", ip,
                         ATTACKER_AGENT)]
    for i in range(40):
        events.append(make_event(rng, when + timedelta(seconds=12 * (i + 1)), victim,
                                 "s3.amazonaws.com", "GetObject", ip, ATTACKER_AGENT,
                                 params={"bucketName": BUCKET, "key": f"export/file-{i:03d}.csv"}))
    return attack_rows(events, "s3_exfiltration")


def no_mfa_login(rng, when, victim="dave", ip=None, agent=None):
    """Un utilisateur se connecte à la console sans MFA, depuis son IP habituelle."""
    if ip is None:
        ip, agent = USERS["dave"]
    events = [make_event(rng, when, victim, "signin.amazonaws.com", "ConsoleLogin", ip, agent,
                         mfa=False, login="Success")]
    return attack_rows(events, "no_mfa_login")


def persistence_access_key(rng, when, actor="carol", target="alice", ip="198.51.100.44"):
    """Un compte compromis crée une clé d'accès et un mot de passe pour un autre utilisateur."""
    params = {"userName": target}
    events = [
        make_event(rng, when, actor, "iam.amazonaws.com", "CreateAccessKey", ip,
                   ATTACKER_AGENT, params=params),
        make_event(rng, when + timedelta(minutes=1), actor, "iam.amazonaws.com",
                   "CreateLoginProfile", ip, ATTACKER_AGENT, params=params),
    ]
    return attack_rows(events, "persistence_access_key")


# --- Mode étendu : jeu de données pour le machine learning -------------------------------

AGENTS = ["aws-cli/2.15.0", "Boto3/1.34.0", "console.amazonaws.com", "terraform/1.6.0"]
BASE_ROLES = {"alice": "developer", "bob": "analyst", "carol": "developer", "dave": "admin"}
ROLE_CYCLE = ["developer", "analyst", "admin", "developer", "analyst", "developer", "analyst"]

ROLE_ACTIONS = {
    "developer": [
        ("ec2.amazonaws.com", "DescribeInstances"),
        ("s3.amazonaws.com", "GetObject"),
        ("s3.amazonaws.com", "PutObject"),
        ("lambda.amazonaws.com", "ListFunctions"),
        ("logs.amazonaws.com", "FilterLogEvents"),
        ("cloudwatch.amazonaws.com", "DescribeAlarms"),
    ],
    "analyst": [
        ("s3.amazonaws.com", "ListBucket"),
        ("s3.amazonaws.com", "GetObject"),
        ("athena.amazonaws.com", "StartQueryExecution"),
        ("athena.amazonaws.com", "GetQueryResults"),
        ("quicksight.amazonaws.com", "DescribeDashboard"),
    ],
    "admin": [
        ("iam.amazonaws.com", "ListUsers"),
        ("iam.amazonaws.com", "GetUser"),
        ("ec2.amazonaws.com", "DescribeInstances"),
        ("cloudtrail.amazonaws.com", "LookupEvents"),
        ("cloudwatch.amazonaws.com", "DescribeAlarms"),
    ],
}


def build_users(count):
    """Les 4 premiers utilisateurs sont ceux du mode de base ; les suivants sont générés."""
    users = {}
    for index in range(count):
        if index < len(USERS):
            name = list(USERS)[index]
            ip, agent = USERS[name]
            role = BASE_ROLES[name]
        else:
            name = f"user{index + 1:02d}"
            ip = f"203.0.113.{20 + index}"
            agent = AGENTS[index % len(AGENTS)]
            role = ROLE_CYCLE[index % len(ROLE_CYCLE)]
        users[name] = {
            "ip": ip,
            "agent": agent,
            "role": role,
            "start": 7 + index % 4,
            "region": "eu-west-1" if index % 5 == 4 else REGION,
        }
    return users


def normal_activity_extended(rng, start, days, users):
    """Activité normale variée : rôles, horaires décalés, week-ends calmes."""
    rows = []
    for day in range(days):
        base = start + timedelta(days=day)
        weekend = base.weekday() >= 5
        for name, user in users.items():
            if weekend and rng.random() > 0.15:
                continue
            count = rng.randint(1, 4) if weekend else rng.randint(5, 14)
            login_time = base.replace(hour=user["start"], minute=rng.randint(0, 59),
                                      second=rng.randint(0, 59))
            rows.append((make_event(rng, login_time, name, "signin.amazonaws.com",
                                    "ConsoleLogin", user["ip"], user["agent"], mfa=True,
                                    region=user["region"]), "normal", 0))
            for _ in range(count):
                when = base.replace(hour=rng.randint(user["start"], user["start"] + 8),
                                    minute=rng.randint(0, 59), second=rng.randint(0, 59))
                source, action = rng.choice(ROLE_ACTIONS[user["role"]])
                rows.append((make_event(rng, when, name, source, action, user["ip"],
                                        user["agent"], region=user["region"]), "normal", 0))
    return rows


def benign_rows(events, scenario):
    """Anomalies légitimes : inhabituelles mais pas malveillantes (is_attack = 0)."""
    return [(event, scenario, 0) for event in events]


def benign_new_employee(rng, when, admin, users):
    """Un administrateur crée le compte d'un nouvel employé."""
    user = users[admin]
    new = f"new-hire-{rng.randint(10, 99)}"
    args = (user["ip"], user["agent"])
    events = [
        make_event(rng, when, admin, "iam.amazonaws.com", "CreateUser", *args,
                   params={"userName": new}),
        make_event(rng, when + timedelta(minutes=1), admin, "iam.amazonaws.com",
                   "AttachUserPolicy", *args,
                   params={"userName": new,
                           "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
        make_event(rng, when + timedelta(minutes=2), admin, "iam.amazonaws.com",
                   "CreateLoginProfile", *args, params={"userName": new}),
    ]
    return benign_rows(events, "benign_new_employee")


def benign_audit_tool(rng, when, admin, users):
    """Un outil d'audit lit de nombreuses informations IAM en quelques minutes."""
    user = users[admin]
    calls = ["ListUsers", "ListRoles", "ListGroups", "ListPolicies",
             "GetAccountSummary", "ListMFADevices", "GetAccountPasswordPolicy"]
    events = [make_event(rng, when + timedelta(seconds=15 * i), admin, "iam.amazonaws.com",
                         name, user["ip"], "audit-tool/1.0") for i, name in enumerate(calls)]
    return benign_rows(events, "benign_audit_tool")


def benign_backup_job(rng, when, name, users):
    """Une sauvegarde de nuit lit une trentaine d'objets S3 depuis l'IP habituelle."""
    user = users[name]
    night = when.replace(hour=2, minute=0, second=0)
    events = [make_event(rng, night + timedelta(seconds=14 * i), name, "s3.amazonaws.com",
                         "GetObject", user["ip"], "backup-agent/2.1",
                         params={"bucketName": "example-backup-bucket",
                                 "key": f"nightly/part-{i:03d}.bak"},
                         region=user["region"]) for i in range(25)]
    return benign_rows(events, "benign_backup_job")


def benign_vpn_login(rng, when, name, users):
    """Une connexion avec MFA depuis une IP inhabituelle (VPN, déplacement)."""
    user = users[name]
    ip = f"192.0.2.{rng.randint(1, 254)}"
    events = [make_event(rng, when, name, "signin.amazonaws.com", "ConsoleLogin", ip,
                         user["agent"], mfa=True, region=user["region"])]
    for i in range(3):
        source, action = rng.choice(ROLE_ACTIONS[user["role"]])
        events.append(make_event(rng, when + timedelta(minutes=5 * (i + 1)), name, source,
                                 action, ip, user["agent"], region=user["region"]))
    return benign_rows(events, "benign_vpn_login")


def benign_typo_logins(rng, when, name, users):
    """Deux mots de passe erronés puis une connexion réussie avec MFA."""
    user = users[name]
    args = (user["ip"], user["agent"])
    events = [
        make_event(rng, when, name, "signin.amazonaws.com", "ConsoleLogin", *args,
                   mfa=False, login="Failure", region=user["region"]),
        make_event(rng, when + timedelta(seconds=20), name, "signin.amazonaws.com",
                   "ConsoleLogin", *args, mfa=False, login="Failure", region=user["region"]),
        make_event(rng, when + timedelta(seconds=45), name, "signin.amazonaws.com",
                   "ConsoleLogin", *args, mfa=True, login="Success", region=user["region"]),
    ]
    return benign_rows(events, "benign_typo_logins")


def crypto_mining(rng, when, victim="alice", ip="198.51.100.33"):
    """Un compte compromis lance de grosses instances dans des régions inhabituelles.

    Aucune règle du catalogue ne vise ce scénario : il sert à voir ce que le machine learning
    repère en plus des règles (régions rares, erreurs de quota, volume d'appels EC2).
    """
    regions = ["ap-southeast-1", "eu-central-1"]
    events = []
    for i in range(6):
        failed = i in (3, 5)
        events.append(make_event(
            rng, when + timedelta(seconds=40 * i), victim, "ec2.amazonaws.com", "RunInstances",
            ip, ATTACKER_AGENT, params={"instanceType": "p3.8xlarge", "maxCount": 4},
            error_code="InstanceLimitExceeded" if failed else None, region=regions[i % 2]))
    return attack_rows(events, "crypto_mining")


def _escalation(rng, when, victim, users, ip):
    return privilege_escalation(rng, when, actor=victim, ip=ip,
                                new_user=f"svc-{rng.randint(100, 999)}")


def _credentials(rng, when, victim, users, ip):
    return credential_abuse(rng, when, victim=victim, ip=ip)


def _recon(rng, when, victim, users, ip):
    return iam_recon(rng, when, victim=victim, ip=ip)


def _evasion(rng, when, victim, users, ip):
    return defense_evasion(rng, when, victim=victim, ip=ip)


def _exfiltration(rng, when, victim, users, ip):
    return s3_exfiltration(rng, when, victim=victim, ip=ip)


def _no_mfa(rng, when, victim, users, ip):
    user = users[victim]
    return no_mfa_login(rng, when, victim=victim, ip=user["ip"], agent=user["agent"])


def _persistence(rng, when, victim, users, ip):
    others = [name for name in users if name != victim] or [victim]
    return persistence_access_key(rng, when, actor=victim, target=rng.choice(others), ip=ip)


def _mining(rng, when, victim, users, ip):
    return crypto_mining(rng, when, victim=victim, ip=ip)


EXTENDED_ATTACKS = [_escalation, _credentials, _recon, _evasion, _exfiltration, _no_mfa,
                    _persistence, _mining]

# (fonction, nombre d'occurrences, utilisateur : administrateur ou n'importe lequel)
BENIGN_SCENARIOS = [
    (benign_new_employee, 2, "admin"),
    (benign_audit_tool, 2, "admin"),
    (benign_backup_job, 2, "any"),
    (benign_vpn_login, 3, "any"),
    (benign_typo_logins, 4, "any"),
]


def random_time(rng, start, days, first_day, hour=None):
    """Un instant aléatoire à partir de `first_day`, pendant les heures de bureau par défaut."""
    day = rng.randint(first_day, days - 1)
    hours = rng.randint(9, 17) if hour is None else hour
    return start + timedelta(days=day, hours=hours, minutes=rng.randint(0, 59),
                             seconds=rng.randint(0, 59))


def extended_dataset(rng, start, days, user_count, repeats):
    """Activité normale variée + anomalies bénignes + attaques répétées."""
    users = build_users(user_count)
    names = list(users)
    admins = [name for name in names if users[name]["role"] == "admin"] or names
    first_day = max(1, days // 3)  # les attaques arrivent quand l'historique existe

    rows = normal_activity_extended(rng, start, days, users)
    for builder, occurrences, who in BENIGN_SCENARIOS:
        for _ in range(occurrences):
            name = rng.choice(admins if who == "admin" else names)
            rows += builder(rng, random_time(rng, start, days, 1), name, users)
    for _ in range(repeats):
        for attack in EXTENDED_ATTACKS:
            victim = rng.choice(names)
            ip = f"198.51.100.{rng.randint(1, 254)}"
            rows += attack(rng, random_time(rng, start, days, first_day), victim, users, ip)
    return rows


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
    parser.add_argument("--days", type=int, default=None,
                        help="nombre de jours (défaut : 5 en mode de base, 30 en mode étendu)")
    parser.add_argument("--seed", type=int, default=42, help="graine aléatoire (reproductibilité)")
    parser.add_argument("--out", default="data/generated", help="dossier de sortie")
    parser.add_argument("--extended", action="store_true",
                        help="jeu de données pour le machine learning")
    parser.add_argument("--users", type=int, default=None,
                        help="nombre d'utilisateurs (mode étendu, défaut : 20)")
    parser.add_argument("--attack-repeats", type=int, default=None,
                        help="occurrences de chaque attaque (mode étendu, défaut : 3)")
    args = parser.parse_args()

    if not args.extended and (args.users is not None or args.attack_repeats is not None):
        parser.error("--users et --attack-repeats nécessitent --extended")
    days = args.days or (30 if args.extended else 5)
    if args.extended and days < 7:
        parser.error("le mode étendu demande au moins 7 jours")

    rng = random.Random(args.seed)
    start = datetime(2026, 11, 10, tzinfo=timezone.utc)

    if args.extended:
        rows = extended_dataset(rng, start, days, args.users or 20, args.attack_repeats or 3)
    else:
        rows = normal_activity(rng, start, days)
        for scenario, day, hour, minute in SCENARIOS:
            when = start + timedelta(days=min(day, days - 1), hours=hour, minutes=minute)
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
