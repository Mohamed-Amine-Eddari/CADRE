---
name: Security report
about: Signaler une vulnérabilité (divulgation responsable)
title: '[SECURITY] '
labels: security
assignees: Mohamed-Amine-Eddari
---

**Pour les vulnérabilités critiques, envoyez un email à
eddarimedamine@gmail.com plutôt que d'ouvrir une issue publique.**

## Résumé

Une description courte de la vulnérabilité.

## Sévérité

- [ ] Critique (exécution de code, escalade de privilèges)
- [ ] Élevée (accès non autorisé à des données sensibles)
- [ ] Moyenne (fuite d'information limitée)
- [ ] Faible (impact minimal)

## Composant affecté

- [ ] Orchestrateur (`src/cadre/orchestrateur.py`)
- [ ] Catalogue
- [ ] Coffre-fort
- [ ] Anonymisation
- [ ] WinRM
- [ ] Sigma
- [ ] Kibana
- [ ] Docker
- [ ] Autre : ...

## Étapes de reproduction

1. ...
2. ...
3. ...

## Impact

Quel est l'impact concret ?

## Preuve de concept (PoC)

```python
# Si possible, un PoC minimal
```

## Versions affectées

- Version(s) : [e.g. 1.0.0]
- Commit : [hash si connu]

## Correction suggérée (optionnel)

Si vous avez une idée de la correction.

## Divulgation coordonnée

- [ ] J'accepte une divulgation coordonnée après correction
- [ ] Je préfère rester anonyme

## Contact

Email ou moyen de contact (si différent de GitHub).
