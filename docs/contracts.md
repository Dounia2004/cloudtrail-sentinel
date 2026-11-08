# Contrats d'interface (à valider ensemble en semaine 1)

Ces trois contrats permettent de travailler en parallèle. Tout changement se discute
à deux et se note dans `docs/decisions.md`.

## 1. Table `events` (SQLite)

| Colonne | Type | Description |
|---|---|---|
| `event_id` | TEXT (clé primaire) | Identifiant unique de l'événement |
| `event_time` | TEXT | Date ISO 8601 en UTC |
| `event_source` | TEXT | Ex. `iam.amazonaws.com` |
| `event_name` | TEXT | Ex. `AttachUserPolicy` |
| `aws_region` | TEXT | Ex. `us-east-1` |
| `identity_type` | TEXT | `IAMUser`, `AssumedRole`, `Root`… |
| `identity_name` | TEXT | Nom de l'identité (clé de corrélation) |
| `identity_arn` | TEXT | ARN fictif (compte `123456789012`) |
| `source_ip` | TEXT | IP de documentation (`203.0.113.x`, `198.51.100.x`) |
| `user_agent` | TEXT | Agent utilisateur |
| `mfa_used` | INTEGER | 1, 0 ou NULL si non applicable |
| `error_code` | TEXT | NULL si succès |
| `login_result` | TEXT | `Success` ou `Failure` pour les connexions console, sinon NULL |
| `request_params` | TEXT | JSON sérialisé |
| `scenario` | TEXT | Étiquette du scénario (données synthétiques) |
| `is_attack` | INTEGER | 1 si événement d'attaque, sinon 0 |

## 2. Format d'une alerte (JSON)

```json
{
  "alert_id": "a-0001",
  "identity": "alice",
  "detection_source": "rule",
  "rule_id": "IAM-001",
  "mitre_technique": "T1098",
  "score": 87,
  "event_ids": ["e-101", "e-102"],
  "first_seen": "2026-11-10T10:24:00Z",
  "last_seen": "2026-11-10T10:27:00Z",
  "description": "Attribution de privilèges administrateur"
}
```

`detection_source` vaut `rule`, `ml` ou `combined`. `score` va de 0 à 100.

## 3. Routes de l'API

| Méthode | Route | Rôle |
|---|---|---|
| GET | `/health` | Vérifier que l'API répond |
| GET | `/events` | Liste filtrable (`identity`, `from`, `to`, `event_name`) |
| GET | `/alerts` | Liste des alertes (`min_score`, `identity`) |
| GET | `/alerts/{alert_id}` | Détail d'une alerte |
| GET | `/identities/{name}/timeline` | Chronologie corrélée d'une identité |
| GET | `/stats` | Alertes actives, score maximal, répartition |
