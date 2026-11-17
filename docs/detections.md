# Catalogue des règles de détection

Ce document décrit les 12 règles de détection de CloudTrail Sentinel : ce qu'elles repèrent,
leurs seuils réels, la technique MITRE ATT&CK associée, leurs limites et les faux positifs
probables. Les règles sont dans `src/detection/rules/` (un fichier par règle) et sont appliquées
par `src/detection/engine.py`.

> Les seuils sont des valeurs de départ, ajustables en paramètre de `detect()`.
> Les codes MITRE sont à vérifier sur https://attack.mitre.org avant le rendu final.

**Statut : les 12 règles sont implémentées et testées** (un cas positif et un cas négatif au
minimum par règle). Le score indiqué est le score de base lié à la gravité (faible 20,
moyenne 50, haute 80, critique 95) ; le module de scoring pourra le recalculer.

## Vue d'ensemble

| ID | Règle | Condition et seuils | MITRE | Gravité (score) | Alertes sur les données de test |
|---|---|---|---|---|---|
| IAM-001 | Droits admin attribués | `AttachUserPolicy`, `AttachRolePolicy` ou `AttachGroupPolicy` réussi avec la politique `AdministratorAccess` | T1098 | Haute (80) | 1 |
| IAM-002 | Nouvelle version de politique | `CreatePolicyVersion` réussi avec `setAsDefault` à vrai | T1098 | Haute (80) | 0 |
| IAM-003 | Politique en ligne ajoutée | `PutUserPolicy`, `PutRolePolicy` ou `PutGroupPolicy` réussi | T1098 | Moyenne (50) | 0 |
| IAM-004 | Clé d'accès pour un autre compte | `CreateAccessKey` réussi dont l'utilisateur ciblé est différent de l'appelant | T1098.001 | Haute (80) | 1 |
| IAM-005 | Nouvel utilisateur ou profil de connexion | `CreateUser` ou `CreateLoginProfile` réussi | T1136.003 | Moyenne (50) | 2 |
| IAM-006 | Rafale de reconnaissance IAM | Au moins 5 appels IAM `List*` ou `Get*` en 5 minutes, dont au moins 4 types différents | T1087.004 | Moyenne (50) | 1 |
| LOG-001 | Journalisation coupée | `StopLogging`, `DeleteTrail` ou `UpdateTrail` réussi | T1562.008 | Critique (95) | 2 |
| AUTH-001 | Connexion sans MFA | `ConsoleLogin` réussi sans MFA | T1078.004 | Moyenne (50) | 3 |
| AUTH-002 | Échecs puis succès | Au moins 5 échecs de connexion en 10 minutes, puis un succès dans les 10 minutes qui suivent | T1110 | Haute (80) | 1 |
| AUTH-003 | IP jamais vue | Première apparition d'une IP pour une identité ayant au moins 5 événements d'historique | T1078.004 | Moyenne (50) | 6 |
| AUTH-004 | Usage du compte root | Tout événement du compte root, réussi ou non | T1078.004 | Haute (80) | 0 |
| S3-001 | Lectures S3 en masse | Au moins 10 lectures S3 (`GetObject`, `ListBucket`, `ListObjects`, `ListObjectsV2`) en 10 minutes | T1530 | Haute (80) | 1 |

Les « données de test » sont les fixtures de `tests/fixtures/` (81 événements, 7 scénarios
d'attaque). Les règles IAM-002, IAM-003 et AUTH-004 n'ont pas encore de scénario dans le
générateur : elles sont testées avec des événements écrits à la main.

## Détail par règle

### IAM-001 : droits admin attribués
- **Pourquoi** : se donner `AdministratorAccess` (toutes les actions sur toutes les ressources) est l'escalade de privilèges la plus directe.
- **Faux positifs probables** : un administrateur qui configure légitimement un compte.
- **Limites** : une politique personnalisée équivalente à l'administrateur n'est pas détectée ; seul le nom exact de la politique gérée AWS est reconnu.

### IAM-002 : nouvelle version de politique
- **Pourquoi** : remplacer le contenu d'une politique existante permet de donner tous les droits sans en attacher une nouvelle.
- **Faux positifs probables** : une mise à jour normale d'une politique.
- **Limites** : le contenu de la politique (`policyDocument`) n'est pas analysé.

### IAM-003 : politique en ligne ajoutée
- **Pourquoi** : une politique en ligne est attachée directement à une identité, donc moins visible qu'une politique gérée.
- **Faux positifs probables** : un outil d'automatisation d'infrastructure.
- **Limites** : le contenu de la politique n'est pas analysé.

### IAM-004 : clé d'accès pour un autre compte
- **Pourquoi** : une clé d'accès offre un accès permanent à un autre compte (persistance).
- **Faux positifs probables** : un administrateur qui dépanne un collègue.
- **Limites** : sans `userName` dans la requête, la clé est créée pour soi-même et aucune alerte n'est émise.

### IAM-005 : nouvel utilisateur ou profil de connexion
- **Pourquoi** : créer un compte, ou un mot de passe pour un compte existant, est un moyen de garder un accès.
- **Faux positifs probables** : l'arrivée d'un nouvel employé.
- **Limites** : pas de distinction entre création légitime et malveillante hors du contexte (heure, auteur, IP), que la corrélation et le scoring prendront en charge.

### IAM-006 : rafale de reconnaissance IAM
- **Pourquoi** : l'attaquant explore utilisateurs, rôles et politiques avant d'agir.
- **Faux positifs probables** : un outil d'audit.
- **Limites** : un script qui répète un seul type d'appel (par exemple `ListUsers` en boucle) n'est pas signalé ; les appels refusés sont ignorés.

### LOG-001 : journalisation coupée
- **Pourquoi** : sans journalisation, plus aucune détection n'est possible. C'est la seule règle de gravité critique.
- **Faux positifs probables** : une opération de maintenance planifiée.
- **Limites** : une tentative refusée (`errorCode` présent) ne déclenche pas d'alerte, alors qu'elle reste intéressante pour un analyste.

### AUTH-001 : connexion sans MFA
- **Pourquoi** : sans second facteur, un mot de passe volé suffit pour entrer.
- **Faux positifs probables** : un compte de service ou un compte qui n'a pas encore activé le MFA.
- **Limites** : seules les connexions réussies sont examinées.

### AUTH-002 : échecs puis succès
- **Pourquoi** : une série d'échecs suivie d'un succès indique qu'un mot de passe a probablement été deviné.
- **Faux positifs probables** : un utilisateur qui oublie son mot de passe.
- **Limites** : des échecs répétés **sans** succès ne déclenchent pas cette règle (force brute qui échoue non signalée).

### AUTH-003 : IP jamais vue
- **Pourquoi** : une identité qui agit depuis une adresse jamais utilisée peut avoir été compromise. Une seule alerte par nouvelle adresse.
- **Faux positifs probables** : télétravail, voyage, VPN, changement de réseau.
- **Limites** : l'historique est celui des événements analysés ; une identité avec moins de 5 événements n'est pas évaluée ; l'IP n'est pas géolocalisée ; les adresses de services AWS (`*.amazonaws.com`) sont ignorées.

### AUTH-004 : usage du compte root
- **Pourquoi** : le compte root a tous les droits et ne devrait presque jamais servir.
- **Faux positifs probables** : une opération rare qui exige légitimement le compte root.
- **Limites** : une alerte par événement ; une session root longue produit plusieurs alertes (la corrélation les regroupera).

### S3-001 : lectures S3 en masse
- **Pourquoi** : télécharger beaucoup d'objets en peu de temps ressemble à de l'exfiltration de données.
- **Faux positifs probables** : une sauvegarde ou une migration de données.
- **Limites** : la taille des données et la sensibilité du bucket ne sont pas prises en compte.

## Couverture des scénarios

| Scénario | Règles visées |
|---|---|
| `privilege_escalation` | IAM-001, IAM-005 |
| `credential_abuse` | AUTH-002 |
| `iam_recon` | IAM-006 |
| `defense_evasion` | LOG-001 |
| `s3_exfiltration` | S3-001 |
| `no_mfa_login` | AUTH-001 |
| `persistence_access_key` | IAM-004, IAM-005 |

AUTH-003 se déclenche en plus dans les scénarios qui utilisent une IP nouvelle. Règles sans
scénario dédié : IAM-002, IAM-003, AUTH-004.

## Limites générales
- Les règles regardent des événements isolés ou des rafales : elles ne reconstituent pas encore la chronologie complète d'une attaque (rôle de la corrélation par identité).
- Les appels refusés sont ignorés par presque toutes les règles.
- Les seuils sont choisis à la main sur des données synthétiques ; ils devront être réglés sur des données plus réalistes.
- Les logs et les règles ont été conçus ensemble : les résultats d'évaluation sont donc optimistes.

## Lancer la détection et l'évaluation

```powershell
python -m src.detection.engine
python -m src.evaluation.rules_eval
python -m src.evaluation.rules_eval --markdown docs/evaluation_rules.md
```
