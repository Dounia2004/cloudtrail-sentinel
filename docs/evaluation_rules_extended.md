# Évaluation des règles de détection (sans machine learning)

5087 événements, 210 d'attaque, 68 alertes.

Niveau événement : précision 73%, rappel 93%, F1 82% (vrais positifs 195, faux positifs 72, faux négatifs 15).

## Par règle

| Règle | Alertes | Vraies | Fausses | Précision |
|---|---|---|---|---|
| IAM-001 | 3 | 3 | 0 | 100% |
| IAM-002 | 0 | 0 | 0 | - |
| IAM-003 | 0 | 0 | 0 | - |
| IAM-004 | 3 | 3 | 0 | 100% |
| IAM-005 | 10 | 6 | 4 | 60% |
| IAM-006 | 5 | 3 | 2 | 60% |
| LOG-001 | 6 | 6 | 0 | 100% |
| AUTH-001 | 9 | 9 | 0 | 100% |
| AUTH-002 | 3 | 3 | 0 | 100% |
| AUTH-003 | 24 | 21 | 3 | 88% |
| AUTH-004 | 0 | 0 | 0 | - |
| S3-001 | 5 | 3 | 2 | 60% |

## Par scénario

| Scénario | Événements | Signalés | Rappel | Détecté | Règles cibles (règles déclenchées) |
|---|---|---|---|---|---|
| privilege_escalation | 9 | 9 | 100% | oui | 2/2 (AUTH-001, AUTH-003, IAM-001, IAM-005) |
| credential_abuse | 21 | 21 | 100% | oui | 1/1 (AUTH-001, AUTH-002, AUTH-003) |
| iam_recon | 24 | 24 | 100% | oui | 1/1 (AUTH-003, IAM-006) |
| defense_evasion | 6 | 6 | 100% | oui | 1/1 (AUTH-003, LOG-001) |
| s3_exfiltration | 123 | 123 | 100% | oui | 1/1 (AUTH-003, S3-001) |
| no_mfa_login | 3 | 3 | 100% | oui | 1/1 (AUTH-001) |
| persistence_access_key | 6 | 6 | 100% | oui | 2/2 (AUTH-003, IAM-004, IAM-005) |
| crypto_mining | 18 | 3 | 17% | oui | 0/0 (AUTH-003) |

> Limite : les logs synthétiques et les règles ont été conçus ensemble, ces chiffres sont donc optimistes. Ils servent de référence pour comparer le machine learning.
