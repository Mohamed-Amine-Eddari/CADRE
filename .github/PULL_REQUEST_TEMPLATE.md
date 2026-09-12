---
name: Pull Request
about: Soumettre une modification au code
title: '[PR] '
labels: ''
assignees: ''
---

## Description

Brève description de la modification.

## Type de changement

- [ ] Bug fix (non-breaking)
- [ ] Nouvelle fonctionnalité (non-breaking)
- [ ] Breaking change (fix ou feature qui casse la compat)
- [ ] Documentation seule
- [ ] Refactoring
- [ ] Performance
- [ ] Tests seuls

## Tests

- [ ] Tests unitaires ajoutés
- [ ] Tests existants passent
- [ ] Couverture maintenue (≥ 75%)
- [ ] Tests manuels effectués

## Checklist

- [ ] Code formatté (`black src/ tests/`)
- [ ] Lint passé (`ruff check src/ tests/`)
- [ ] Types vérifiés (`mypy src/cadre/`)
- [ ] Audit sécurité (`bandit -r src/`)
- [ ] Documentation à jour (README, docstrings, CHANGELOG)
- [ ] Pas de secrets committés
- [ ] Pas de dépendances ajoutées sans justification
- [ ] Commits au format Conventional Commits

## Issue liée

Fixes #XXX (remplacer par le numéro d'issue)

## Screenshots / Logs (optionnel)

Si pertinent, ajoutez des captures d'écran ou des logs.

## Review checklist (pour le mainteneur)

- [ ] Code review
- [ ] Tests CI passent
- [ ] Documentation cohérente
- [ ] Pas de régression
- [ ] Merge squash
