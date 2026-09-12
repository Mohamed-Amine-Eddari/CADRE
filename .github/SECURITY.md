# Politique de sécurité

CADRE est un outil de recherche/pédagogique conçu pour être exécuté dans
un **laboratoire isolé** (VM host-only, sans accès Internet). Il traite
des credentials et des logs sensibles — voir le modèle de menace complet
dans [`docs/SECURITY.md`](../docs/SECURITY.md) et
[`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md).

## Versions supportées

Projet à version unique (pas de branches de maintenance) : seule la
dernière version de `main` reçoit des correctifs de sécurité.

| Version | Supportée |
|---------|-----------|
| `main` (dernier commit) | ✅ |
| Toute version antérieure | ❌ |

## Signaler une vulnérabilité

**Ne créez pas d'issue publique** pour une vulnérabilité non corrigée.

Deux façons de la signaler de façon responsable :

1. **Security Advisory GitHub** (préféré) — onglet *Security* du dépôt →
   *Report a vulnerability*.
2. **Email direct** : eddarimedamine@gmail.com — décrivez la
   vulnérabilité, les étapes de reproduction, et l'impact estimé.

Un modèle d'issue dédié existe aussi pour les signalements non sensibles
ou déjà publics : [`security_report.md`](ISSUE_TEMPLATE/security_report.md).

## Ce qui est dans le périmètre

- Le code de `src/cadre/` et `dashboard/` (orchestrateur, dashboard web,
  génération/validation de règles Sigma).
- Les scripts de déploiement (`scripts/`, `Dockerfile`,
  `docker-compose.yml`).

## Ce qui est hors périmètre

- Les VM cibles elles-mêmes sont **volontairement affaiblies**
  (firewall/antivirus désactivés) — c'est un choix de conception pour un
  laboratoire d'émulation, documenté dans
  [`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md), pas une
  vulnérabilité de CADRE.
- Les dépendances tierces (Elasticsearch, Kibana, Ollama) : signalez-les
  directement à leurs mainteneurs respectifs. La dépendance transitive
  déjà connue et suivie (`diskcache`, `PYSEC-2026-2447`) est documentée
  dans [`docs/SECURITY.md`](../docs/SECURITY.md).

## Délai de réponse

Ce projet est maintenu par une seule personne (projet étudiant) — pas de
SLA formel, mais un accusé de réception sous 7 jours est visé.
