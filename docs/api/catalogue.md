# Module `cadre.catalogue_attaques`

Catalogue déterministe des techniques MITRE ATT&CK émulées par CADRE.

```{eval-rst}
.. automodule:: cadre.catalogue_attaques
   :members:
   :undoc-members:
   :show-inheritance:
```

## Exemple d'utilisation

```python
from cadre.catalogue_attaques import (
    CATALOGUE,
    obtenir_attaque,
    obtenir_par_tactique,
    obtenir_par_technique,
    statistiques_catalogue,
)

# Lister toutes les attaques
print(f"Nombre d'attaques : {len(CATALOGUE)}")

# Trouver une attaque par son ID
attaque = obtenir_attaque("CADRE-EXE-001")
print(f"Nom : {attaque.nom}, Technique : {attaque.technique_mitre}")

# Toutes les attaques de Persistence
attaques_persistence = obtenir_par_tactique("Persistence")
print(f"{len(attaques_persistence)} attaques de persistance")

# Statistiques
stats = statistiques_catalogue()
print(f"Couverture : {stats['par_tactique']}")
```

## Modèle de données

Voir [`AttaqueCatalogue`](#cadre.catalogue_attaques.AttaqueCatalogue) pour
la structure complète d'une entrée du catalogue.

L'attribut clé est `id` qui suit le format `CADRE-XXX-NNN` :

- `CADRE-INI-NNN` : Initial Access
- `CADRE-EXE-NNN` : Execution
- `CADRE-PER-NNN` : Persistence
- `CADRE-PRI-NNN` : Privilege Escalation
- `CADRE-EVA-NNN` : Defense Evasion
- `CADRE-CRE-NNN` : Credential Access
- `CADRE-DIS-NNN` : Discovery
- `CADRE-LAT-NNN` : Lateral Movement
- `CADRE-COL-NNN` : Collection
- `CADRE-COM-NNN` : Command and Control
- `CADRE-EXF-NNN` : Exfiltration
- `CADRE-IMP-NNN` : Impact
- `CADRE-LIN-NNN` : attaques spécifiques Linux (tactique variable selon
  l'entrée — voir le champ `tactique_mitre` de chaque attaque)
- `CADRE-IA-NNN` : attaques découvertes par l'agent IA (`cadre suggest`),
  conservées dans le catalogue personnel (`catalogue_perso.json`) après
  validation TP/FP réelle — jamais dans le catalogue natif ci-dessus
  (tactique variable, voir `tactique_mitre` de chaque attaque)
