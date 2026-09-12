# Guide d'installation CADRE

> ⏱**Durée totale estimée** : 45 minutes
> **Configuration minimale** : 16 Go RAM, 100 Go disque, Windows 10/11 ou Linux

---

## Table des matières

1. [Prérequis système](#1-prérequis-système)
2. [Installation de Docker](#2-installation-de-docker)
3. [Installation de Python](#3-installation-de-python)
4. [Installation de VirtualBox](#4-installation-de-virtualbox)
5. [Installation de CADRE](#5-installation-de-cadre)
6. [Configuration de la VM Windows cible](#6-configuration-de-la-vm-windows-cible)
7. [Vérification finale](#7-vérification-finale)

---

## 1. Prérequis système

### Matériel

| Composant | Minimum | Recommandé |
|-----------|---------|------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 Go | 32 Go (pour VM + Docker) |
| Disque | 100 Go libres | SSD 256 Go |
| Réseau | Ethernet | Ethernet Gigabit |

### Logiciels

- **OS** : Windows 10/11 (build 19041+) ou Linux (Ubuntu 22.04+)
- **Hyperviseur** activé dans le BIOS (VT-x / AMD-V)

---

## 2. Installation de Docker

### Windows 10/11

1. Téléchargez [Docker Desktop pour Windows](https://www.docker.com/products/docker-desktop/)
2. Lancez l'installateur `.exe`
3. **Cochez impérativement** l'option **"Use WSL 2 instead of Hyper-V"**
4. Redémarrez le PC
5. Lancez Docker Desktop et attendez que le whale icon devienne fixe

```powershell
# Vérification
docker --version
docker compose version
```

### Linux (Ubuntu 22.04+)

```bash
# Installation
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

# Docker Compose v2
sudo apt install docker-compose-plugin
```

---

## 3. Installation de Python

### Windows

1. Téléchargez [Python 3.13](https://www.python.org/downloads/)
2. **Cochez** "Add Python to PATH" lors de l'installation
3. **Cochez** "Install py launcher"

```powershell
python --version
pip --version
```

### Linux

```bash
sudo apt install python3.13 python3.13-venv python3-pip
```

---

## 4. Installation de VirtualBox

1. Téléchargez [VirtualBox 7.x](https://www.virtualbox.org/wiki/Downloads)
2. Installez le **VirtualBox Extension Pack** correspondant
3. Redémarrez

### Configuration réseau VirtualBox

Créez un réseau **Host-Only** :

1. **File** → **Host Network Manager** → **Create**
2. Configurez :
   - **IPv4 Address** : `192.168.56.1`
   - **IPv4 Network Mask** : `255.255.255.0`
   - **DHCP Server** : Enabled (192.168.56.100 - 192.168.56.254)

---

## 5. Installation de CADRE

```bash
# Cloner le dépôt
git clone https://github.com/Mohamed-Amine-Eddari/cadre.git
cd cadre

# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement
# Windows :
venv\Scripts\activate
# Linux :
source venv/bin/activate

# Installer les dépendances
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

### Vérification

```bash
cadre --version
cadre --help
```

---

## 6. Configuration de la VM Windows cible

### Création de la VM

1. Téléchargez une **ISO Windows 10** (ou 11) officielle
2. Dans VirtualBox : **New** → nommez-la `CADRE-Victim`
3. Configuration recommandée :
   - **RAM** : 4096 Mo
   - **Disque** : 60 Go (dynamiquement alloué)
   - **CPU** : 2 cores
   - **Réseau** : **Host-Only Adapter** (vboxnet0)

### Installation de Sysmon

```powershell
# Télécharger Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Sysmon"

# Télécharger la config SwiftOnSecurity
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\config.xml"

# Installer en tant qu'administrateur
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i config.xml
```

### Installation de Winlogbeat

1. Téléchargez [Winlogbeat 8.x](https://www.elastic.co/downloads/beats/winlogbeat)
2. Décompressez dans `C:\Program Files\Winlogbeat`
3. Éditez `winlogbeat.yml` :

```yaml
winlogbeat.event_logs:
  - name: Application
  - name: System
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational

output.elasticsearch:
  hosts: ["192.168.56.1:9200"]
  username: "elastic"
  password: "VOTRE_MOT_DE_PASSE_ELASTIC"  # pragma: allowlist secret

setup.kibana:
  host: "192.168.56.1:5601"
```

4. Installez le service :

```powershell
cd "C:\Program Files\Winlogbeat"
.\install-service.ps1
Start-Service winlogbeat
```

### Activer WinRM

```powershell
# En tant qu'administrateur
Enable-PSRemoting -Force
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -Enabled True
```

### Créer un utilisateur de test

```powershell
# IMPORTANT : pour CADRE
net user CadreUser "VOTRE_MOT_DE_PASSE" /add
net localgroup administrators CadreUser /add
```

### Désactiver Defender et Firewall (par design pour la cible)

```powershell
# Désactiver Defender
Set-MpPreference -DisableRealtimeMonitoring $true

# Désactiver le firewall (les 3 profils)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

---

## 7. Vérification finale

### Démarrer la stack

```bash
# Dans le répertoire CADRE
docker compose up -d

# Attendre 60 secondes qu'Elastic démarre
```

### Configurer les credentials CADRE

```bash
cadre init
# Répondez aux questions (le mot de passe ne sera jamais affiché)
```

### Tester

```bash
# Vérifier la connectivité
cadre status

# Tester avec une attaque bénigne
cadre cycle --id CADRE-DIS-001

# Lancer un cycle complet
cadre cycle
```

### Logs et dépannage

- Logs CADRE : `./logs/cadre.log.json`
- Logs Docker : `docker compose logs -f`
- Rapports : `./rapports/cycle_*.md`

---

## Problèmes courants

### "Cannot connect to Elasticsearch"

```bash
# Vérifier qu'Elastic répond
curl http://localhost:9200
# Si KO :
docker compose ps
docker compose logs elasticsearch
```

### "WinRM connection refused"

1. Vérifiez que la VM est sur le réseau Host-Only (192.168.56.x)
2. Vérifiez que WinRM est activé : `Test-WSMan` sur la VM
3. Vérifiez que le firewall autorise WinRM (port 5985)

### "Angles morts" sur 100% des attaques

Votre Sysmon n'est probablement pas configuré. Vérifiez :

```powershell
Get-Service Sysmon64
# Doit être "Running"
```

Si Sysmon tourne mais que les EventIDs n'arrivent pas, vérifiez Winlogbeat :

```powershell
# Voir les logs
Get-EventLog -LogName Application -Source Winlogbeat -Newest 10
```

---

## Support

- [GitHub Issues](https://github.com/Mohamed-Amine-Eddari/cadre/issues)
- [Discussions](https://github.com/Mohamed-Amine-Eddari/cadre/discussions)
