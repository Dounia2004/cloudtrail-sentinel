# Protocole d'évaluation ML

- **Séparation par identité** (pas par événement) : évite qu'une même identité
  soit vue à l'entraînement puis testée.
- **Scénario non vu** : `access_key_persistence` est exclu de l'entraînement
  et présent uniquement dans le jeu de test, pour mesurer la généralisation.
- **Isolation Forest** : entraîné sur les fenêtres normales du jeu train uniquement.
- **Graine fixée** : `SEED = 42` partout.
- **Métriques** : precision, recall, F1, matrice de confusion, taux de faux positifs,
  calculées sur le test global puis sur le scénario non vu seul.
- **Limite** : données synthétiques, donc résultats à interpréter avec prudence.
