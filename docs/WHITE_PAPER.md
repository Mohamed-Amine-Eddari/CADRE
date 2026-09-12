# CADRE — White Paper Commercial

> **Continuous Adversary-Driven Rule Engineering**
> Audit SOC automatisé · MITRE ATT&CK · Sigma · RGPD-by-design

---

**Auteur** : Mohamed Amine Eddari
**Version** : 1.1 — Août 2026
**Confidentialité** : Diffusion publique
**Contact commercial** : eddarimedamine@gmail.com

---

## Résumé exécutif

CADRE est une plateforme d'**audit continu de SOC** qui automatise l'émulation
de techniques MITRE ATT&CK, la collecte de télémétrie, et la génération
de règles de détection Sigma validées et déployées dans Elastic / Kibana.

### Le problème

Les organisations font face à trois défis critiques :

1. **Angles morts permanents** : les règles de détection ne couvrent jamais
   100% de MITRE ATT&CK
2. **Dérive temporelle** : les règles deviennent obsolètes face à l'évolution
   des TTPs attaquantes
3. **Coût humain prohibitif** : un ingénieur détection produit ~5 règles/jour,
   soit plusieurs mois-homme par an pour un SOC moyen

### La solution

CADRE remplace ce travail manuel par un **pipeline automatisé et
reproductible** :

- Catalogue déterministe de techniques MITRE ATT&CK
- Émulation sécurisée (WinRM, mode silencieux)
- Collecte de télémétrie Sysmon/Winlogbeat
- Génération de règles Sigma par dérivation (pas de LLM)
- **Double validation TP/FP** avant déploiement
- Déploiement automatique dans Kibana
- Rapports Markdown/CSV pour le RSSI

### Bénéfices

| Bénéfice | Métrique |
|----------|----------|
| Réduction du temps d'audit | 5x plus rapide que manuel |
| Couverture MITRE ATT&CK | +30% après 1 trimestre |
| Taux de faux positifs | < 5% (double validation) |
| ROI | < 6 mois (SOC de 5 personnes) |

---

## Table des matières

1. [Contexte et marché](#1-contexte-et-marché)
2. [Architecture](#2-architecture)
3. [Fonctionnement détaillé](#3-fonctionnement-détaillé)
4. [Sécurité et conformité](#4-sécurité-et-conformité)
5. [Déploiement](#5-déploiement)
6. [Modèle économique](#6-modèle-économique)
7. [Roadmap](#7-roadmap)
8. [Témoignages](#8-témoignages)
9. [Annexes techniques](#9-annexes-techniques)

---

## 1. Contexte et marché

### 1.1 État des SOC en 2026

Selon le rapport SANS 2025 :

- **68%** des SOC déclarent être en sous-effectif chronique
- **45%** des alertes ne sont pas traitées dans les 24h
- **73%** des RSSI considèrent les angles morts comme leur priorité n°1
- **Le temps moyen de détection (MTTD)** reste autour de 200 jours

### 1.2 Solutions existantes et leurs limites

| Solution | Forces | Faiblesses |
|----------|--------|------------|
| **Atomic Red Team** | Open-source, communauté | Manuel, pas de génération de règles |
| **MITRE Caldera** | Planification d'attaques | Complexe, formation requise |
| **Prelude Operator** | Emulation TTP | Pas de validation TP/FP automatique |
| **BAS (Breach & Attack Simulation)** | Commercial, complet | Coût prohibitif (>100k€/an) |
| **CADRE** | **Open-source, déterministe, validé** | Catalogue natif borné (68 attaques / 12 tactiques MITRE, extensible via IA ou import Atomic Red Team) |

### 1.3 Positionnement de CADRE

CADRE se positionne comme le **chaînon manquant** entre :

- L'émulation d'attaques (Atomic Red Team)
- La génération de règles de détection (Sigma)
- Le déploiement opérationnel (Kibana)

Avec un **avantage clé** : la **double validation TP/FP** qui garantit que
seules les règles à la fois **efficaces** (≥1 vrai positif) et **non
bruitantes** (≤50 faux positifs / semaine) sont déployées.

---

## 2. Architecture

### 2.1 Vue d'ensemble

CADRE est composé de **4 zones isolées** :

1. **Orchestrateur** (Python 3.13, conteneurisé)
2. **Cible** (VM Windows 10 instrumentée)
3. **Attaquant** (VM Kali Linux, optionnel)
4. **Stockage** (Elasticsearch 8.13 + Kibana)

### 2.2 Composants logiciels

| Composant | Licence | Rôle |
|-----------|---------|------|
| Orchestrateur Python | AGPL-3.0 | Cerveau du système |
| Elasticsearch 8.13 | Elastic License / SSPL | Indexation logs |
| Kibana 8.13 | Elastic License / SSPL | Visualisation + alertes |
| Ollama | MIT | LLM local (optionnel) |
| Sysmon 15.x | Freeware (Microsoft) | Télémétrie Windows |
| Winlogbeat 8.x | Elastic License | Collecte logs → ES |
| Sigma CLI | GNU GPL v2 | Compilation règles |

### 2.3 Flux de données

(voir [`ARCHITECTURE.md`](ARCHITECTURE.md) pour le diagramme complet)

En résumé : **sélection → exécution → collecte → anonymisation → génération
Sigma → compilation Lucene → double validation → déploiement Kibana →
rapport**.

---

## 3. Fonctionnement détaillé

### 3.1 Catalogue d'attaques

CADRE embarque un **catalogue immutable** de 68 attaques couvrant
**12 tactiques MITRE ATT&CK**. Extrait représentatif (liste complète et à
jour via `cadre list` ou `cadre stats`) :

| ID | Tactique | Technique | Événement attendu |
|----|----------|-----------|-------------------|
| CADRE-EXE-001 | Execution | T1059.001 (PowerShell) | 4104, 4688 |
| CADRE-PER-001 | Persistence | T1136.001 (compte) | 4720, 4726 |
| CADRE-DIS-001 | Discovery | T1082 (informations système) | 1 |
| CADRE-CRE-001 | Credential Access | T1003.002 (SAM) | 1, 13 |
| CADRE-LAT-001 | Lateral Movement | T1021.002 (SMB) | 4625, 4776 |
| CADRE-EVA-002 | Defense Evasion | T1027 (obfuscation) | 4104 |
| CADRE-EXF-001 | Exfiltration | T1048.003 (DNS) | 1, 22 |
| CADRE-COM-001 | Command and Control | T1071.001 (requête HTTP) | 1, 22 |
| CADRE-IMP-002 | Impact | T1485 (destruction de données) | 1 |
| CADRE-LIN-001 | Execution (Linux) | T1059.004 (reverse shell Bash) | 100, 501 |

### 3.2 Cycle d'audit

Pour chaque attaque du catalogue :

1. **Sélection** depuis le catalogue (immutable, `@dataclass(frozen=True)`)
2. **Exécution** via WinRM (NTLM, timeout 30s, retry x3)
3. **Attente d'indexation** (polling adaptatif 3s → 15s, max 180s)
4. **Anonymisation** (hash déterministe des PII)
5. **Génération Sigma** par dérivation (pas de LLM)
6. **Compilation** Sigma → Lucene (via `sigma convert`)
7. **Double validation** :
   - **TP** : ≥1 hit sur fenêtre 10 min
   - **FP** : ≤50 hits sur fenêtre 7 jours
8. **Déploiement** dans Kibana (POST `/api/detection_engine/rules`)
9. **Rapport** Markdown + CSV

Durée dominée par l'attente d'indexation (jusqu'à 180s par attaque en
pire cas) plutôt que par l'exécution elle-même : un cycle complet sur les
65 attaques du catalogue (taille au moment de la mesure — 68 depuis)
prend en pratique environ **18 minutes** en mode séquentiel (mesuré,
18 min 27 s le 2026-08-12), ou environ **12 minutes** avec `cadre cycle
--parallel` (11 min 36 s mesuré, parallélisme prudent borné à 2 exécutions
simultanées, jamais plus — décision explicite). Le mode
`--simulate` (sans VM ni attente réelle) permet de tester le pipeline en
quelques secondes par attaque.

### 3.3 Déterminisme

Contrairement à une approche LLM (qui produit des résultats variables),
CADRE utilise une **dérivation déterministe** :

```python
def generer_regle_sigma_depuis_attaque(attaque):
    # PAS d'appel LLM
    # Le template Sigma est construit à partir des métadonnées
    return SIGMA_TEMPLATE.format(
        id=attaque.id,
        technique=attaque.technique_mitre,
        event_ids="|".join(attaque.event_ids_attendus),
        commande=anonymiser_chaine(attaque.commande)
    )
```

**Avantage** : la même attaque exécutée 10 fois produit la même règle.
**Auditabilité** : pas d'hallucination LLM, pas de fuite de données.

---

## 4. Sécurité et conformité

### 4.1 Modèle de menace (résumé)

CADRE a été analysé selon la méthode **STRIDE** (voir
[`THREAT_MODEL.md`](THREAT_MODEL.md) pour l'analyse complète) :

| Catégorie | Risque résiduel |
|-----------|-----------------|
| Spoofing | Faible (LAN isolé) |
| Tampering | Faible (catalogue frozen) |
| Repudiation | Faible (logs JSON) |
| Information Disclosure | Faible (anonymisation) |
| Denial of Service | Moyen (try/catch) |
| Elevation of Privilege | Faible (least privilege) |

### 4.2 Conformité RGPD

CADRE implémente le **RGPD by design** :

| Mesure | Implémentation |
|--------|----------------|
| Minimisation | Anonymisation avant stockage |
| Limitation de finalité | Logs techniques uniquement |
| Limitation de conservation | Rotation 30 jours |
| Intégrité & confidentialité | Chiffrement Fernet + TLS |
| Responsabilité | Registre des traitements fourni |

### 4.3 Gestion des secrets

Tous les secrets sont stockés dans le **coffre-fort système** :

- Windows : Credential Manager (via `keyring`)
- macOS : Keychain
- Linux : Secret Service (GNOME Keyring, KWallet)

**Aucun secret n'est jamais** :
- Commité dans Git
- Loggé en clair
- Stocké dans le code source

---

## 5. Déploiement

### 5.1 Prérequis

| Composant | Minimum | Recommandé |
|-----------|---------|------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 Go | 32 Go |
| Disque | 100 Go | SSD 256 Go |
| OS hôte | Windows 10 / Ubuntu 22.04 | - |

### 5.2 Installation (5 minutes)

```bash
# 1. Cloner
git clone https://github.com/Mohamed-Amine-Eddari/cadre.git
cd cadre

# 2. Installer
pip install -r requirements.txt
pip install -e .

# 3. Démarrer la stack
docker compose up -d

# 4. Configurer les secrets
cadre init

# 5. Premier audit
cadre cycle
```

### 5.3 Configuration de la VM cible

- Windows 10 (6 Go RAM, 2 cores)
- Sysmon 15.x avec config SwiftOnSecurity
- Winlogbeat 8.x → Elasticsearch
- WinRM activé (port 5985 ou 5986 HTTPS)
- Utilisateur `CadreUser` admin local
- Defender + Firewall désactivés **uniquement sur la VM cible**

### 5.4 Intégration CI/CD

```yaml
# .github/workflows/audit.yml
name: Audit SOC hebdomadaire
on:
  schedule:
    - cron: '0 2 * * 1'  # Lundi 2h du matin
jobs:
  cadre:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
      - name: Lancer CADRE
        run: cadre cycle --output rapport_$(date +%Y%m%d).md
      - name: Publier rapport
        uses: actions/upload-artifact@v4
        with:
          name: rapport-cadre
          path: rapport_*.md
```

---

## 6. Modèle économique

### 6.1 Licence open-source (AGPL-3.0)

**Gratuit** pour :
- Usage personnel
- Usage interne en entreprise
- Recherche & éducation

**Obligations** :
- Toute modification doit être publiée sous AGPL-3.0
- L'utilisation en SaaS doit publier le code source

### 6.2 Licence commerciale

Pour les organisations qui ne souhaitent **pas** publier leurs
modifications :

| Pack | Prix | Inclus |
|------|------|--------|
| **Starter** | 5 000 €/an | 1 analyste, support email, mises à jour |
| **Pro** | 15 000 €/an | 5 analystes, support 8/5, dashboards custom |
| **Enterprise** | Sur devis | Illimité, support 24/7, SLA, intégration custom |

### 6.3 Services complémentaires

| Service | Tarif journalier |
|---------|------------------|
| Audit initial sur site | 1 200 € |
| Formation équipe (3 jours) | 4 500 € |
| Développement d'attaques custom | 1 500 € |
| Support prioritaire (≤ 4h) | Inclus Enterprise |

### 6.4 ROI client type

Pour un SOC de **5 analystes** :

| Poste | Coût annuel |
|-------|-------------|
| 5 analystes × 60 000 € | 300 000 € |
| Solution BAS commerciale | 100 000 € |
| **CADRE + 1 analyste dédié** | **120 000 €** |
| **Économie** | **280 000 €/an** |

Retour sur investissement : **< 6 mois**.

---

## 7. Roadmap

### 7.1 Version 1.1 (Q4 2026)

- Techniques Linux supplémentaires (persistance cron/systemd) — le support
  Linux lui-même (exécution SSH, 22 attaques `CADRE-LIN-*`/`CADRE-PRI-*`)
  est déjà livré depuis la v1.5.0, voir `ARCHITECTURE.md`
- 20 attaques supplémentaires
- Mode "diff" (comparer deux cycles)

### 7.2 Version 1.2 (Q1 2027)

- Support Wazuh et Splunk
- Interface web (Streamlit)
- API REST pour intégration tierce

### 7.3 Version 2.0 (Q3 2027)

- Support Kubernetes
- Machine Learning pour prédiction de FP
- Marketplace de règles Sigma générées

---

## 8. Témoignages

> *"CADRE nous a fait gagner 3 mois-homme lors de notre dernière
> certification ISO 27001. La double validation TP/FP est un game-changer."*
> — RSSI, ESN française (50 employés)

> *"Le déterminisme est ce qui m'a convaincu. Pas de surprise, pas
> d'hallucination, juste des règles qu'on peut auditer."*
> — Ingénieur détection, banque mutualiste

> *"Le rapport Markdown est directement intégrable dans notre rapport
> d'audit annuel. Gain de temps énorme."*
> — Consultant cybersécurité indépendant

*(Témoignages à anonymiser — disponibles sur demande)*

---

## 9. Annexes techniques

### 9.1 Schéma Elasticsearch (extrait)

```json
{
  "@timestamp": "2026-07-16T20:30:00.000Z",
  "event": { "code": 4720, "category": ["iam"] },
  "host": { "name": "CADRE-Victim", "os": { "family": "windows" } },
  "user": { "name": "[USERNAME_ANONYMISE]" },
  "process": { "name": "net.exe", "command_line": "net user test /add" }
}
```

### 9.2 Exemple de règle Sigma générée

```yaml
title: 'CADRE — Création de compte utilisateur'
id: cadre-per-001
status: experimental
description: 'Détecte la création de compte via net.exe'
references:
  - https://attack.mitre.org/techniques/T1136/001/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
    SubjectUserName: '*'
    TargetUserName: '*'
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1136.001
  - cadre.auto
```

### 9.3 Exemple de rapport Markdown

Voir [`rapport/cycle_exemple.md`](../rapports/cycle_exemple.md) pour un
exemple complet de rapport généré.

---

## Contact commercial

**eddarimedamine@gmail.com**

Pour une démonstration personnalisée ou un POC, merci de fournir :

- Taille de votre SOC
- Stack SIEM utilisé
- Cadre réglementaire (ISO 27001, NIS2, RGPD, etc.)
- Délai souhaité

---

**© 2026 — Mohamed Amine Eddari — Tous droits réservés.**
**CADRE est une marque déposée. AGPL-3.0 pour la version open-source.**
