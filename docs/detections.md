# Catalogue des règles de détection

Ce document liste les règles de détection de CloudTrail Sentinel. Chaque règle précise
l'événement surveillé, la condition qui le rend suspect, la technique MITRE ATT&CK associée,
la gravité et les faux positifs probables.

> Les seuils (N, durées) sont des valeurs de départ, à ajuster sur les données.
> Les codes MITRE sont à vérifier sur https://attack.mitre.org avant le rendu final.

| ID | Règle | Condition | MITRE | Gravité | Faux positif probable |
|---|---|---|---|---|---|
| IAM-001 | Droits admin attribués | `AttachUserPolicy`, `AttachRolePolicy` ou `AttachGroupPolicy` avec `AdministratorAccess` | T1098 | Haute | Un administrateur qui configure un compte |
| IAM-002 | Nouvelle version de politique | `CreatePolicyVersion` avec `setAsDefault` à vrai | T1098 | Haute | Mise à jour normale d'une politique |
| IAM-003 | Politique en ligne ajoutée | `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy` | T1098 | Moyenne | Automatisation d'infrastructure |
| IAM-004 | Clé d'accès pour un autre compte | `CreateAccessKey` où l'utilisateur ciblé est différent de l'appelant | T1098.001 | Haute | Un administrateur qui dépanne un collègue |
| IAM-005 | Nouvel utilisateur ou profil de connexion | `CreateUser`, `CreateLoginProfile` | T1136.003 | Moyenne | Arrivée d'un nouvel employé |
| IAM-006 | Rafale de reconnaissance | Au moins N appels IAM `List*` ou `Get*` distincts en 5 minutes | T1087.004 | Moyenne | Un outil d'audit |
| LOG-001 | Journalisation coupée | `StopLogging`, `DeleteTrail`, `UpdateTrail` | T1562.008 | Critique | Maintenance planifiée |
| AUTH-001 | Connexion sans MFA | `ConsoleLogin` réussi sans MFA | T1078.004 | Moyenne | Compte de service sans MFA |
| AUTH-002 | Échecs puis succès | Au moins 5 échecs de `ConsoleLogin`, puis un succès en 10 minutes | T1110 | Haute | Utilisateur qui oublie son mot de passe |
| AUTH-003 | IP jamais vue | Première IP source observée pour cette identité | T1078.004 | Moyenne | Télétravail, voyage, VPN |
| AUTH-004 | Usage du compte root | `userIdentity.type` égal à `Root` | T1078.004 | Haute | Opérations rares mais légitimes |
| S3-001 | Lectures S3 en masse | Au moins N `GetObject` ou `ListBucket` en 10 minutes | T1530 | Haute | Sauvegarde ou migration |

## Remarques

- Les règles IAM-006, AUTH-002 et S3-001 sont **à seuil et à fenêtre de temps** : elles comptent
  les événements d'une même identité sur une période.
- AUTH-001 et AUTH-002 s'appuient sur la colonne `login_result` de la table `events`.
- Chaque règle sera implémentée dans un fichier dédié de `src/detection/rules/`, avec un test
  sur un cas positif et un cas négatif.
