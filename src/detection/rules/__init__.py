"""Registre des règles de détection.

Une règle = un module qui définit RULE_ID, MITRE, SEVERITY et une fonction
detect(events) -> list[Alert]. Pour ajouter une règle : créer le module, puis l'ajouter à RULES.
"""
from src.detection.rules import (
    auth_002,
    iam_001,
    iam_002,
    iam_003,
    iam_004,
    iam_005,
    iam_006,
    log_001,
    s3_001,
)

RULES = [iam_001, iam_002, iam_003, iam_004, iam_005, iam_006, log_001, auth_002, s3_001]
