"""Registre des règles de détection.

Une règle = un module qui définit RULE_ID, MITRE, SEVERITY et une fonction
detect(events) -> list[Alert]. Pour ajouter une règle : créer le module, puis l'ajouter à RULES.
"""
from src.detection.rules import iam_001, iam_002, iam_003, iam_004, iam_005, log_001

RULES = [iam_001, iam_002, iam_003, iam_004, iam_005, log_001]
