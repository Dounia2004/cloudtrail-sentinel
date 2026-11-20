# Résultats d'évaluation

Test : 1155 fenêtres, dont 13 d'attaque. Scénario non vu à l'entraînement : `persistence_access_key`.

## Métriques globales

| modèle | tp | fp | tn | fn | precision | recall | f1 | fpr |
|---|---|---|---|---|---|---|---|---|
| règles | 13 | 3 | 1139 | 0 | 0.812 | 1.000 | 0.897 | 0.003 |
| isolation_forest | 8 | 44 | 1098 | 5 | 0.154 | 0.615 | 0.246 | 0.039 |
| combiné (règles OU IF) | 13 | 45 | 1097 | 0 | 0.224 | 1.000 | 0.366 | 0.039 |
| random_forest (réf.) | 12 | 2 | 1140 | 1 | 0.857 | 0.923 | 0.889 | 0.002 |

## Part de fenêtres signalées par scénario

| scénario | type | fenêtres | règles | isolation_forest | combiné (règles OU IF) | random_forest (réf.) |
|---|---|---|---|---|---|---|
| credential_abuse | attaque | 2 | 1.000 | 1.000 | 1.000 | 1.000 |
| crypto_mining | attaque | 1 | 1.000 | 1.000 | 1.000 | 1.000 |
| defense_evasion | attaque | 2 | 1.000 | 0.000 | 1.000 | 1.000 |
| iam_recon | attaque | 1 | 1.000 | 1.000 | 1.000 | 1.000 |
| persistence_access_key | attaque | 3 | 1.000 | 0.333 | 1.000 | 1.000 |
| privilege_escalation | attaque | 2 | 1.000 | 0.500 | 1.000 | 1.000 |
| s3_exfiltration | attaque | 2 | 1.000 | 1.000 | 1.000 | 0.500 |
| benign_backup_job | normal | 1 | 1.000 | 1.000 | 1.000 | 0.000 |
| benign_new_employee | normal | 1 | 1.000 | 1.000 | 1.000 | 1.000 |
| benign_typo_logins | normal | 1 | 0.000 | 0.000 | 0.000 | 0.000 |
| benign_vpn_login | normal | 2 | 0.500 | 0.000 | 0.500 | 0.500 |
| normal | normal | 1137 | 0.000 | 0.037 | 0.037 | 0.000 |

## Matrices de confusion

### règles

|   | prédit : normal | prédit : attaque |
|---|---|---|
| réel : normal | 1139 | 3 |
| réel : attaque | 0 | 13 |

### isolation_forest

|   | prédit : normal | prédit : attaque |
|---|---|---|
| réel : normal | 1098 | 44 |
| réel : attaque | 5 | 8 |

### combiné (règles OU IF)

|   | prédit : normal | prédit : attaque |
|---|---|---|
| réel : normal | 1097 | 45 |
| réel : attaque | 0 | 13 |

### random_forest (réf.)

|   | prédit : normal | prédit : attaque |
|---|---|---|
| réel : normal | 1140 | 2 |
| réel : attaque | 1 | 12 |

## Alertes par règle

| règle | alertes | sur_attaque | sur_normal |
|---|---|---|---|
| AUTH-001 | 9 | 2 | 0 |
| AUTH-002 | 3 | 1 | 0 |
| AUTH-003 | 24 | 10 | 1 |
| IAM-001 | 3 | 1 | 0 |
| IAM-004 | 3 | 3 | 0 |
| IAM-005 | 10 | 4 | 2 |
| IAM-006 | 5 | 1 | 0 |
| LOG-001 | 6 | 4 | 0 |
| S3-001 | 5 | 1 | 1 |
