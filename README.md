# CloudTrail Sentinel

Détection d'anomalies sur les logs AWS CloudTrail : règles heuristiques mappées MITRE ATT&CK,
Isolation Forest, scoring 0–100, corrélation par identité et dashboard SOC.

> Projet de fin d'année (PFA) – EMSI, 2026/2027
> Auteurs : Dounia BARRI et Aymen EL OUAHBI · Encadrant : M. Moumen Idriss

**Statut : en cours de développement (semaine 1).**

## Architecture

1. Sources de données : logs synthétiques, datasets publics
2. Ingestion et stockage : Pydantic, Pandas, SQLite
3. Détection : règles (MITRE ATT&CK) + Isolation Forest
4. Scoring et évaluation : score 0–100, corrélation, precision/recall/F1
5. Exposition : API FastAPI, dashboard Streamlit, agent LLM optionnel

Détails : `docs/contracts.md` (schéma de données, format d'alerte, API).

## Démarrage rapide (développement)

```bash
python -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -r requirements.txt
pre-commit install
cp .env.example .env
pytest
```

## Règles de contribution

- Jamais de push direct sur `main` : branche + pull request + relecture par l'autre.
- Toujours `git pull` avant de commencer.
- Aucune donnée réelle, aucun secret dans le dépôt (valeurs fictives uniquement).
- Commits au format Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`).

## Licence

MIT
