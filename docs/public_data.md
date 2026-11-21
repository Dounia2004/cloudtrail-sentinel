# Validation sur données publiques (flaws.cloud)

Source : Summit Route, flaws.cloud CloudTrail logs (2020). Logs réels anonymisés, **non étiquetés** : pas de precision ni de recall, seulement un contrôle de robustesse et un aperçu qualitatif.

- Événements lus : 50000, valides : 50000 (100.0%), rejetés : 0
- Fenêtres (identité x heure) : 608 pour 8 identités
- Alertes des règles : 2684

## Alertes par règle

| Règle | Alertes |
|---|---|
| AUTH-004 | 2472 |
| AUTH-003 | 176 |
| IAM-006 | 22 |
| IAM-002 | 9 |
| IAM-005 | 2 |
| IAM-004 | 2 |
| IAM-003 | 1 |

## Événements les plus fréquents

| Événement | Occurrences |
|---|---|
| RunInstances | 35914 |
| DescribeSnapshotAttribute | 2520 |
| DescribeSnapshots | 980 |
| DescribeInstances | 959 |
| GetBucketAcl | 883 |
| AssumeRole | 734 |
| CreateDefaultVpc | 326 |
| GetCallerIdentity | 277 |
| GetPolicy202224v2 | 204 |
| DescribeVolumes | 187 |
