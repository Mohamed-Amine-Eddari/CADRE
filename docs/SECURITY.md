# Politique de sécurité CADRE

> **À lire avant tout déploiement en production.**
> Ce document complète le [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Signaler une vulnérabilité

**eddarimedamine@gmail.com** (chiffrement PGP recommandé)
⏱**Délai de réponse** : 72 heures ouvrées
**Divulgation coordonnée** : 90 jours maximum avant disclosure publique

Pour les vulnérabilités critiques, merci d'inclure :
- Description détaillée et vecteur d'exploitation
- Étapes de reproduction (PoC si possible)
- Impact estimé
- Versions affectées

## Versions supportées

| Version | Statut | Fin de support |
|---------|--------|----------------|
| 1.0.x   | Supportée | 2027-12-31 |
| < 1.0   | Non supportée | - |

## Bonnes pratiques de déploiement

### 1. Isolation réseau

```bash
# Créer un réseau Host-Only (jamais ponté vers Internet)
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0
```

**Règle absolue** : la VM cible ne doit JAMAIS avoir accès à Internet.
Même chose pour l'orchestrateur en phase d'exécution.

### 2. Gestion des secrets

```bash
# Bon : via le coffre-fort
cadre init --set CADRE_VM_PASS=$(getpass)

# Mauvais : en clair dans le shell
export CADRE_VM_PASS="motdepasse"  # Visible dans `ps`, l'historique, etc.

# Très mauvais : dans le code
CADRE_VM_PASS = "motdepasse"  # JAMAIS !
```

### 3. Rotation des credentials

| Secret | Fréquence de rotation |
|--------|----------------------|
| `CADRE_VM_PASS` | 90 jours |
| `CADRE_ELASTIC_PASS` | 90 jours |
| `CADRE_KIBANA_TOKEN` | 180 jours |
| `CADRE_MASTER_KEY` (Fernet) | 365 jours |

Procédure :

```bash
# 1. Changer le mot de passe côté VM/Elastic
# 2. Mettre à jour le coffre
cadre init --set CADRE_VM_PASS=$(getpass -s "Nouveau mot de passe: ")
# 3. Vérifier
cadre status
```

**Cas particulier de `CADRE_ELASTIC_PASS`** : le mettre à jour dans le
coffre-fort (étape 2 ci-dessus) ne suffit PAS. Winlogbeat (VM Windows) et
Auditbeat (VM Linux) lisent leur propre mot de passe depuis leur fichier de
configuration local (`winlogbeat.yml` / `auditbeat.yml`, écrit une fois lors
de l'installation initiale — voir `docs/INSTALL.md`), jamais depuis le
coffre-fort CADRE. Une rotation qui s'arrête à l'étape 2 laisse les deux
agents authentifier avec l'ANCIEN mot de passe : ils échouent silencieusement,
la télémétrie s'arrête, et `cadre status` reste vert (il ne teste que
l'accessibilité d'Elasticsearch/Kibana/la VM, pas l'état des agents).

Procédure complète pour `CADRE_ELASTIC_PASS` :

```bash
# 1. Changer le mot de passe côté Elasticsearch (ex. elasticsearch-reset-password)
# 2. Mettre à jour le coffre-fort CADRE
cadre init --set CADRE_ELASTIC_PASS=$(getpass -s "Nouveau mot de passe: ")
# 3. Repousser le nouveau mot de passe vers winlogbeat.yml/auditbeat.yml
#    et redémarrer les deux agents (WinRM + SSH, voir synchronise_secrets.py)
cadre secrets-sync-beats
# 4. Vérifier que la télémétrie reprend (une attaque de test doit être détectée)
cadre cycle --id CADRE-DIS-001
```

### 4. Vérification TLS (Elasticsearch / Kibana)

Par **défaut, la vérification du certificat TLS est désactivée**
(`reseau.verifier_tls()` renvoie `False`). C'est un **choix conscient et
local** : en laboratoire, Elastic et Kibana tournent sur `127.0.0.1`, en
HTTP clair ou avec un certificat auto-signé — vérifier le certificat
n'apporterait aucune protection réelle (rien ne quitte la machine) et
empêcherait simplement la connexion.

**En production** (services derrière de vrais certificats) : réactiver la
vérification via une seule variable d'environnement :

```bash
export CADRE_VERIFY_TLS=1
```

Le code ne dissémine jamais de `verify=False` codé en dur : tous les appels
passent par cette source unique, ce qui rend la politique auditable et
modifiable en un seul endroit. Scan `bandit` : **0 finding HIGH/MEDIUM**.

### 4 bis. Durcissement du transport WinRM (production)

Par **défaut (laboratoire)**, CADRE parle à la VM en **HTTP clair sur le port
5985**, avec authentification **NTLM** et **sans vérifier le certificat** —
acceptable uniquement sur un réseau host-only isolé, sans tiers sur le réseau.

**En production**, on durcit le transport **sans modifier le code**, via
quatre variables d'environnement (lues par `OrchestrateurCADRE._charger_config_env`,
voir [`orchestrateur.py`](../src/cadre/orchestrateur.py)) :

```bash
export CADRE_WINRM_SCHEME=https           # HTTP -> HTTPS (défaut: http)
export CADRE_WINRM_PORT=5986              # 5985 -> 5986 (défaut: 5985)
export CADRE_WINRM_TRANSPORT=kerberos     # NTLM -> Kerberos (défaut: ntlm)
export CADRE_WINRM_CERT_VALIDATION=validate  # ignore -> validate (défaut: ignore)
```

| Variable | Labo (défaut) | Production recommandée |
|----------|---------------|------------------------|
| `CADRE_WINRM_SCHEME` | `http` | `https` |
| `CADRE_WINRM_PORT` | `5985` | `5986` |
| `CADRE_WINRM_TRANSPORT` | `ntlm` | `kerberos` (domaine AD) |
| `CADRE_WINRM_CERT_VALIDATION` | `ignore` | `validate` |

L'endpoint est alors construit dynamiquement : `https://<vm>:5986/wsman`.
Prérequis côté VM pour HTTPS : un **écouteur WinRM HTTPS** avec un certificat
de confiance :

```powershell
# Sur la VM cible (PowerShell administrateur)
$cert = New-SelfSignedCertificate -DnsName "cadre-vm" -CertStoreLocation Cert:\LocalMachine\My
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * `
    -CertificateThumbprint $cert.Thumbprint -Force
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -LocalPort 5986 `
    -Protocol TCP -Action Allow
```

> Le transport `kerberos` nécessite le paquet Python `pykerberos`/`requests-kerberos`
> et une machine jointe à un domaine Active Directory. En l'absence de ces
> prérequis, conserver `ntlm` (déjà chiffré côté HTTPS via le canal TLS).

Les mêmes variables `CADRE_VM_IP`, `CADRE_ELASTIC_URL`, `CADRE_KIBANA_URL`,
`CADRE_INDEX_PATTERN` permettent de pointer CADRE vers une autre VM / un autre
SIEM sans toucher au code. **Aucune de ces variables n'est un secret** : les
mots de passe, eux, restent exclusivement dans le coffre-fort.

### 5. Logs et audit

- **Rétention** : 30 jours minimum, 1 an recommandé
- **Format** : JSON structuré (un événement par ligne)
- **Localisation** : `./logs/cadre.log.json`
- **Intégrité** : SHA-256 journalier, archivage WORM si possible

```bash
# Rotation automatique (cron quotidien)
0 0 * * * find /opt/cadre/logs -name "*.json" -mtime +30 -delete
0 0 * * * sha256sum /opt/cadre/logs/cadre.log.json > /var/log/cadre.sha256
```

### 6. Mises à jour et audit des dépendances

```bash
# Vérifier les vulnérabilités connues (pip-audit, gratuit, sans compte —
# remplace `safety` qui exige désormais une authentification).
pip install pip-audit
pip-audit -r requirements.txt --desc

# Mettre à jour CADRE
pip install --upgrade cadre
```

Le même contrôle tourne en CI (job `security` de
[`cadre-ci.yml`](../.github/workflows/cadre-ci.yml)) et localement via
`make security` ou `make ci`.

#### Vulnérabilités connues suivies (exception documentée)

| ID | Paquet | Sévérité | Statut | Raison |
|----|--------|----------|--------|--------|
| `PYSEC-2026-2447` | `diskcache` (transitif via pySigma) | **5,2/10 — Moyen** (CVSS 4.0, vecteur **local**) | ⏳ Suivie | **Aucune version corrective publiée** à ce jour. Dépendance de pySigma, cœur du projet : ni supprimable ni upgradable. |

**Pourquoi le risque réel est limité ici** : l'exploitation (désérialisation
`pickle` non sûre) exige qu'un attaquant ait *déjà* un accès en écriture au
répertoire de cache local — ce n'est pas une porte d'entrée réseau. Dans
l'environnement de labo isolé de CADRE (VM host-only sans accès Internet,
§ 1 ci-dessus, usage mono-utilisateur), un attaquant capable d'écrire dans
ce répertoire aurait de toute façon déjà un accès à la machine largement
suffisant pour causer plus de dégâts par d'autres moyens. Le paquet est
**surveillé** : mise à jour dès qu'un correctif est publié côté `diskcache`
ou que pySigma change de dépendance de cache.

**Toute AUTRE vulnérabilité fait échouer `make security`/`make ci` en
local** (`pip-audit --ignore-vuln PYSEC-2026-2447`, voir `Makefile`) :
l'exception ne masque que cette advisory précise et sans correctif. En CI
GitHub Actions (`cadre-ci.yml`), l'étape `pip-audit` est en
`continue-on-error` pour la même raison (la CVE reste visible dans les
logs, elle ne bloque simplement pas le pipeline) — le mécanisme diffère du
local (exception ciblée vs étape non bloquante), l'effet recherché est le
même : ne jamais masquer silencieusement une autre vulnérabilité.

**Abonnement aux alertes** : Watcher le repo GitHub pour les
`Security Advisories`.

## Conformité RGPD

CADRE traite des logs qui peuvent contenir des **données personnelles**
(adresses IP, noms d'utilisateur, emails). Conformément au RGPD :

### Base légale

- **Intérêt légitime** (article 6.1.f) : test de la sécurité du SI
- **Test sur environnement isolé** (rec. CNIL "tests d'intrusion")

### Mesures techniques

| Type de donnée | Mesure |
|----------------|--------|
| Adresses IP | Anonymisation systématique |
| Noms d'utilisateur | Hash déterministe |
| Emails | Suppression |
| Mots de passe | Jamais loggés |

Voir [`anonymisation.py`](../src/cadre/anonymisation.py) pour l'implémentation.

### Registre des traitements

Pour un déploiement en production, ajouter au registre des traitements :

```
Nom : Audit SOC automatisé (CADRE)
Finalité : Vérification de l'efficacité des règles de détection
Base légale : Intérêt légitime (sécurité du SI)
Catégories de données : Logs techniques (IP, usernames)
Durée de conservation : 30 jours
Mesures de sécurité : Chiffrement, anonymisation, contrôle d'accès
```

## Audit et pentest

Si vous mandatez un pentesteur pour tester CADRE :

### À FAIRE

- Lui fournir un compte `CadreUser` non privilégié
- Lui donner un accès lecture aux logs
- Cadrer le périmètre sur **votre VM de test** uniquement
- Signer une autorisation écrite

### À NE PAS FAIRE

- Lancer le pentest sur la production
- Partager le mot de passe Elastic/Kibana hors période d'audit
- Oublier de révoquer les accès après la mission

## Chiffrement

### Au repos

- Coffre-fort : Fernet (AES-128-CBC + HMAC-SHA256)
- Clé maître : permissions `0600`, sauvegardée hors-ligne
- Logs : pas de chiffrement natif (volumétrie) — monter `/logs` sur
  volume chiffré (LUKS, BitLocker)

### En transit

| Canal | Chiffrement |
|-------|-------------|
| WinRM HTTP (5985) | À remplacer par HTTPS (5986) en prod |
| WinRM HTTPS (5986) | TLS 1.2+ |
| HTTP Elastic (9200) | À remplacer par HTTPS en prod |
| HTTPS Elastic (9243) | TLS 1.2+ |
| Docker interne | Réseau bridge isolé |

```yaml
# docker-compose.yml (production)
elasticsearch:
  environment:
    - xpack.security.http.ssl.enabled=true
    - xpack.security.http.ssl.key=/certs/elastic.key
    - xpack.security.http.ssl.certificate=/certs/elastic.crt
```

## Checklist de déploiement sécurisé

Avant de passer en production, vérifier :

- [ ] Tous les mots de passe sont dans le coffre (jamais en clair)
- [ ] WinRM en HTTPS (5986), pas HTTP (5985)
- [ ] Elastic/Kibana en HTTPS avec certificats valides
- [ ] La VM cible est sur Host-Only (pas d'Internet)
- [ ] Le pare-feu Windows est actif (sauf exception documentée)
- [ ] Les logs sont sur un volume chiffré
- [ ] La rotation des logs est configurée (cron)
- [ ] Les dépendances sont à jour (`pip-audit -r requirements.txt`)
- [ ] Un audit `bandit` est passé sans erreur haute
- [ ] Le modèle de menace a été revu par le RSSI
- [ ] Une procédure de réponse à incident existe
- [ ] L'équipe est formée (utilisation du mode dry-run)

## Engagement de l'auteur

L'auteur s'engage à :

1. **Répondre sous 72h** à toute divulgation de vulnérabilité
2. **Publier un correctif** dans les 30 jours pour les vulnérabilités critiques
3. **Maintenir à jour** les dépendances (détection automatique via Dependabot)
4. **Documenter** les CVE dans [`CHANGELOG.md`](../CHANGELOG.md)
5. **Reconnaître** les contributeurs sécurité (hall of fame)

## Licence et responsabilité

CADRE est distribué sous **AGPL-3.0**. L'auteur ne pourra être tenu
responsable d'une utilisation non autorisée ou non conforme à la
présente politique de sécurité.

> *"La sécurité est un processus, pas un produit."* — Bruce Schneier
