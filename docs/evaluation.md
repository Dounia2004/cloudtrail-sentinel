# Résultats d'évaluation

Test : 1889 fenêtres, dont 57 d'attaque. Scénario non vu à l'entraînement : `persistence_access_key`.

## Métriques globales

| modèle | tp | fp | tn | fn | precision | recall | f1 | fpr |
|---|---|---|---|---|---|---|---|---|
| règles | 56 | 6 | 1826 | 1 | 0.903 | 0.982 | 0.941 | 0.003 |
| isolation_forest | 28 | 84 | 1748 | 29 | 0.250 | 0.491 | 0.331 | 0.046 |
| combiné (règles OU IF) | 57 | 84 | 1748 | 0 | 0.404 | 1.000 | 0.576 | 0.046 |
| random_forest (réf.) | 55 | 1 | 1831 | 2 | 0.982 | 0.965 | 0.973 | 0.001 |

## Part de fenêtres signalées par scénario

| scénario | type | fenêtres | règles | isolation_forest | combiné (règles OU IF) | random_forest (réf.) |
|---|---|---|---|---|---|---|
| credential_abuse | attaque | 9 | 1.000 | 0.889 | 1.000 | 1.000 |
| crypto_mining | attaque | 6 | 0.833 | 0.667 | 1.000 | 1.000 |
| defense_evasion | attaque | 6 | 1.000 | 0.000 | 1.000 | 0.833 |
| iam_recon | attaque | 4 | 1.000 | 1.000 | 1.000 | 1.000 |
| no_mfa_login | attaque | 7 | 1.000 | 0.000 | 1.000 | 1.000 |
| persistence_access_key | attaque | 10 | 1.000 | 0.300 | 1.000 | 1.000 |
| privilege_escalation | attaque | 8 | 1.000 | 0.250 | 1.000 | 1.000 |
| s3_exfiltration | attaque | 7 | 1.000 | 1.000 | 1.000 | 0.857 |
| benign_backup_job | normal | 2 | 1.000 | 1.000 | 1.000 | 0.000 |
| benign_new_employee | normal | 2 | 1.000 | 1.000 | 1.000 | 0.000 |
| benign_typo_logins | normal | 2 | 0.000 | 0.000 | 0.000 | 0.000 |
| benign_vpn_login | normal | 3 | 0.667 | 1.000 | 1.000 | 0.333 |
| normal | normal | 1823 | 0.000 | 0.042 | 0.042 | 0.000 |

## Matrices de confusion

### règles

|   | prédit : normal | prédit : attaque |
|---|---|---|
| réel : normal | 1826 | 6 |
| réel : attaque | 1 | 56 |

### isolation_forest

|   | prédit : normal | prédit : attaque |
|---|---|---|
| réel : normal | 1748 | 84 |
| réel : attaque | 29 | 28 |

### combiné (règles OU IF)

|   | prédit : normal | prédit : attaque |
|---|---|---|
| réel : normal | 1748 | 84 |
| réel : attaque | 0 | 57 |

### random_forest (réf.)

|   | prédit : normal | prédit : attaque |
|---|---|---|
| réel : normal | 1831 | 1 |
| réel : attaque | 2 | 55 |

## Alertes par règle

| règle | alertes | sur_attaque | sur_normal |
|---|---|---|---|
| AUTH-001 | 30 | 18 | 0 |
| AUTH-002 | 10 | 8 | 0 |
| AUTH-003 | 72 | 43 | 2 |
| IAM-001 | 10 | 5 | 0 |
| IAM-004 | 10 | 10 | 0 |
| IAM-005 | 24 | 15 | 4 |
| IAM-006 | 12 | 4 | 0 |
| LOG-001 | 20 | 12 | 0 |
| S3-001 | 12 | 6 | 2 |
