# Évaluation des règles de détection (sans machine learning)

249 événements, 64 d'attaque, 18 alertes.

Niveau événement : précision 100%, rappel 100%, F1 100% (vrais positifs 64, faux positifs 0, faux négatifs 0).

## Par règle

| Règle | Alertes | Vraies | Fausses | Précision |
|---|---|---|---|---|
| IAM-001 | 1 | 1 | 0 | 100% |
| IAM-002 | 0 | 0 | 0 | - |
| IAM-003 | 0 | 0 | 0 | - |
| IAM-004 | 1 | 1 | 0 | 100% |
| IAM-005 | 2 | 2 | 0 | 100% |
| IAM-006 | 1 | 1 | 0 | 100% |
| LOG-001 | 2 | 2 | 0 | 100% |
| AUTH-001 | 3 | 3 | 0 | 100% |
| AUTH-002 | 1 | 1 | 0 | 100% |
| AUTH-003 | 6 | 6 | 0 | 100% |
| AUTH-004 | 0 | 0 | 0 | - |
| S3-001 | 1 | 1 | 0 | 100% |

## Par scénario

| Scénario | Événements | Signalés | Rappel | Détecté | Règles cibles (règles déclenchées) |
|---|---|---|---|---|---|
| privilege_escalation | 3 | 3 | 100% | oui | 2/2 (AUTH-001, AUTH-003, IAM-001, IAM-005) |
| credential_abuse | 7 | 7 | 100% | oui | 1/1 (AUTH-001, AUTH-002, AUTH-003) |
| iam_recon | 8 | 8 | 100% | oui | 1/1 (AUTH-003, IAM-006) |
| defense_evasion | 2 | 2 | 100% | oui | 1/1 (AUTH-003, LOG-001) |
| s3_exfiltration | 41 | 41 | 100% | oui | 1/1 (AUTH-003, S3-001) |
| no_mfa_login | 1 | 1 | 100% | oui | 1/1 (AUTH-001) |
| persistence_access_key | 2 | 2 | 100% | oui | 2/2 (AUTH-003, IAM-004, IAM-005) |

> Limite : les logs synthétiques et les règles ont été conçus ensemble, ces chiffres sont donc optimistes. Ils servent de référence pour comparer le machine learning.
