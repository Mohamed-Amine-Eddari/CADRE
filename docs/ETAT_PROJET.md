# État du projet et passation

> **Destinataire** : quiconque reprend CADRE après Mohamed Amine Eddari
> (encadrant, futur étudiant PFA). Ce document donne en 5 minutes ce que le
> reste de la documentation demande de reconstituer en fouillant
> `CHANGELOG.md` (long, chronologique) — l'état courant, ce qui est
> vérifié, ce qui est bloqué, et par où continuer.
>
> **Dernière mise à jour** : 2026-09-11.

## 1. État vérifié à cette date

Toute la chaîne qualité est verte sur l'ensemble du projet (pas seulement
un module) :

| Vérification | Résultat |
|---|---|
| `pytest` | **1168 tests, 0 échec, 0 ignoré** |
| Couverture (`--cov=cadre`) | **93,61 %** (seuil CI : 75 %) |
| `ruff check src tests` | Aucune erreur |
| `black --check src tests` | Aucun fichier à reformater |
| `mypy src/cadre` | Aucune erreur (mode strict) |
| `bandit -r src` | 0 problème réel (uniquement des `# nosec` déjà justifiés en commentaire) |
| `detect-secrets scan` | Aucun secret dans les fichiers suivis par Git |
| `pip-audit` | 1 CVE transitive suivie et acceptée (`diskcache`, via pySigma, aucun correctif publié — voir `docs/SECURITY.md` § risques résiduels) |

Reproduire tout ça en une commande : `make ci` (Linux/macOS, ou Windows
sous WSL/Git Bash avec `make` installé — sur un poste Windows sans `make`,
relancer chaque ligne du `Makefile` cible `ci:` individuellement).

## 2. Ce qui fonctionne (vue d'ensemble)

- Catalogue déterministe de 68 attaques MITRE ATT&CK (46 Windows + 22
  Linux, 12 tactiques), exécutées via WinRM (Windows) / SSH (Linux/Kali).
- Détection automatisée : génération de règles Sigma, déploiement Kibana,
  vérification du résultat (TP/FP/FAUX_NÉGATIF) dans Elasticsearch.
- Cycle complet piloté (`cadre cycle` / `cadre loop`), rapports
  Markdown/CSV/HTML/PDF générés automatiquement en fin de cycle.
- Dashboard web (`cadre dashboard`, 12 onglets), découverte IA d'attaques
  (Ollama local), scénarios kill chain, ingestion Atomic Red Team.
- Coffre-fort de secrets (`src/cadre/coffre_fort.py`) : priorité variable
  d'environnement > Windows Credential Manager > `.env` chiffré (Fernet).

Détail complet : `README.md`, `docs/ARCHITECTURE.md`, `docs/GUIDE_PROJET.md`.

## 3. Points bloqués ou fragiles — à connaître AVANT de perdre du temps à les redécouvrir

### 3.1 Conflit SentinelOne / VirtualBox — VM Kali actuellement bloquée

L'agent EDR SentinelOne (installé le 19/08 sur le poste de développement)
fait planter `VBoxHeadless.exe`/`VBoxNetDHCP.exe` (violation d'accès
`0xC0000005`) dès qu'une VM démarre — confirmé par corrélation avec les
logs d'installation du service Windows (< 90 min). C'est un conflit connu
entre agents EDR à hooks noyau et VirtualBox, **externe à CADRE** (aucun
bug côté code). Détail complet : `CHANGELOG.md`, section « Conflit
EDR/hyperviseur ».

- La VM **Windows** a été débloquée définitivement le 22/08 (tâche
  planifiée de contournement).
- La VM **Kali reste bloquée** au moment de la rédaction : la correction
  propre nécessite une exclusion de type Path sur les moteurs d'inspection
  dynamique de SentinelOne (rôle Admin requis sur la console, pas Viewer)
  pour :
  ```
  C:\Program Files\Oracle\VirtualBox\*
  C:\Users\<votre-utilisateur>\VirtualBox VMs\*
  ```
- Effet de bord observé une fois l'exclusion partiellement en place :
  Winlogbeat peut refuser un simple redémarrage de service à cause de la
  protection anti-sabotage (« tamper protection ») de l'EDR — seul un
  **redémarrage complet de la VM Windows** contourne ça de façon fiable.

### 3.2 Historique Git purgé des anciens identifiants (11/09)

Deux anciens mots de passe de labo (Elasticsearch/Kibana, déjà rotés
avant cette purge — voir CHANGELOG, incident CWE-798) étaient encore
lisibles dans l'historique Git déjà public (commit initial inclus).
Historique entièrement réécrit avec `git filter-repo`
(`--replace-text`/`--replace-message`) puis republié par `git push
--force` : plus aucune occurrence dans aucun commit ni message,
vérifié après coup. Sauvegarde complète pré-purge conservée hors dépôt
(`CADRE-backup-avant-purge-20260911.bundle`). Note technique : GitHub
peut retenir en interne des objets « détachés » d'un historique réécrit
pendant une période de grâce (dépôt privé, sans fork ni PR sur ces
commits) — sans incidence puisque les valeurs concernées sont déjà mortes.

### 3.3 Rotation de `CADRE_ELASTIC_PASS` — résolu, mais un réflexe à garder

Winlogbeat et Auditbeat codent chacun leur propre mot de passe
Elasticsearch en dur dans leur configuration, **hors du coffre-fort
CADRE**, et ne le relisent jamais automatiquement. Une rotation de
`CADRE_ELASTIC_PASS` sans action supplémentaire casse silencieusement la
télémétrie (`cadre status` reste pourtant vert — il ne vérifie que la
joignabilité, pas l'authentification des agents).

**Réflexe à garder** : après toute rotation de `CADRE_ELASTIC_PASS`,
lancer immédiatement :
```
cadre secrets-sync-beats
```
Cette commande (`src/cadre/synchronise_secrets.py`, ajoutée le 11/09)
repousse le nouveau mot de passe vers les deux agents et les redémarre.
Procédure complète : `docs/SECURITY.md`, section rotation de secrets.

### 3.4 `diskcache` — CVE transitive sans correctif

`PYSEC-2026-2447`, dépendance transitive de pySigma (cœur du projet),
déjà à sa dernière version publiée : aucun correctif n'existe en amont.
Risque jugé faible et documenté en détail (surface d'exploitation,
conditions requises) dans `docs/SECURITY.md`. À re-vérifier
périodiquement (`pip-audit`) au cas où un correctif sortirait.

### 3.5 Hygiène de l'environnement virtuel local

L'environnement `.venv` de ce poste contient des paquets orphelins
(`safety`, et sa dépendance `nltk` avec ~30 CVE) : résidus d'un outil
remplacé par `pip-audit` (voir `docs/SECURITY.md`), **jamais déclarés**
dans `requirements*.txt` ni utilisés par le code ou la CI — sans impact
réel, mais `pip uninstall safety nltk` nettoierait le `pip-audit` local.

## 4. Où regarder pour aller plus loin

| Besoin | Fichier |
|---|---|
| Historique détaillé de chaque correctif/fonctionnalité | `CHANGELOG.md` |
| Posture de sécurité, procédure de rotation des secrets | `docs/SECURITY.md` |
| Architecture, schéma des composants | `docs/ARCHITECTURE.md` |
| Installation complète (VMs, SIEM, agents) | `docs/INSTALL.md` |
| Guide d'utilisation pas à pas | `docs/GUIDE_PROJET.md` |

## 5. Pistes de continuation naturelles

Aucune de ces pistes n'est un défaut actuel — ce sont des directions
d'extension cohérentes avec l'architecture existante :

- Débloquer définitivement la VM Kali (§ 3.1) puis rejouer les 22
  attaques Linux du catalogue pour confirmer la non-régression.
- Étendre le catalogue à d'autres tactiques MITRE ATT&CK non encore
  couvertes, ou à d'autres OS (macOS).
- Suivre `diskcache` (§ 3.3) jusqu'à publication d'un correctif.
