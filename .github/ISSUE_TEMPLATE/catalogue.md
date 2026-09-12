---
name: 🆕 Nouvelle attaque au catalogue
about: Proposer l'ajout d'une technique MITRE ATT&CK
title: '[CATALOGUE] '
labels: catalogue, enhancement
assignees: ''
---

## Technique MITRE ATT&CK

- **ID** : [e.g. T1003.002]
- **Nom** : [e.g. Security Account Manager]
- **Tactique parente** : [e.g. Credential Access]
- **Sous-technique** : [e.g. SAM]
- **URL** : https://attack.mitre.org/techniques/T1003/002/

## Commande d'émulation

```powershell
# Commande exacte à exécuter sur la VM cible
reg save hklm\sam C:\temp\sam.save
```

## EventIDs Windows attendus

- [ ] 4663
- [ ] 4670
- [ ] 4688
- [x] Autre : 5145

## Faux positifs connus

- Processus de sauvegarde système (`wbadmin.exe`)
- Outils de monitoring interne

## Niveau de risque

- [ ] Faible
- [x] Moyen
- [ ] Élevé

## Prérequis

- Sysmon installé
- Winlogbeat configuré
- Privilèges administrateur

## Durée estimée

5 secondes

## Tests

- [ ] Commande testée manuellement sur la VM cible
- [ ] EventIDs vérifiés dans Kibana
- [ ] Pas de crash VM

## Implémentation

```python
AttaqueCatalogue(
    id="CADRE-CRE-013",
    nom="SAM dump via reg save",
    description="Dump du fichier SAM via la commande reg save",
    technique_mitre="T1003.002",
    tactique_mitre="Credential Access",
    sous_technique="SAM",
    commande="reg save hklm\\sam C:\\Windows\\Temp\\sam.save",
    event_ids_attendus=["4663", "4670"],
    champ_principal="process.command_line",
    faux_positifs_connus=[
        "wbadmin.exe",
    ],
    niveau_risque=NiveauRisque.MOYEN,
    plateforme=Plateforme.WINDOWS,
    references=[
        "https://attack.mitre.org/techniques/T1003/002/",
    ],
    prerequisites=["Privilèges administrateur"],
    duree_estimee_sec=5,
),
```

## Sources

- [Atomic Red Team #T1003.002](https://github.com/redcanaryco/atomic-red-team)
- [LOLBAS](https://lolbas-project.github.io/)
- Documentation interne
