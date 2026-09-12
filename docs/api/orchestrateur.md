# Module `cadre.orchestrateur`

Cerveau de CADRE : orchestre un cycle d'audit complet.

```{eval-rst}
.. automodule:: cadre.orchestrateur
   :members:
   :undoc-members:
   :show-inheritance:
```

## Cycle d'audit

La méthode [`executer_cycle_complet`](#cadre.orchestrateur.OrchestrateurCADRE.executer_cycle_complet)
est le point d'entrée principal. Elle exécute séquentiellement :

1. **Sélection** depuis le catalogue
2. **Exécution** via WinRM
3. **Attente** d'indexation Elastic
4. **Anonymisation** des logs
5. **Génération** de la règle Sigma (déterministe)
6. **Compilation** Sigma → Lucene
7. **Validation** TP/FP
8. **Déploiement** dans Kibana
9. **Rapport** Markdown + CSV

## Déterminisme

Contrairement à une approche LLM, CADRE utilise une **dérivation
déterministe** des règles Sigma. La méthode
[`generer_regle_sigma_depuis_attaque`](#cadre.orchestrateur.OrchestrateurCADRE.generer_regle_sigma_depuis_attaque)
garantit qu'une même attaque produit toujours la même règle.

## Exemple

```python
from cadre.orchestrateur import OrchestrateurCADRE

config = {
    "vm_ip": "192.168.56.104",
    "vm_user": "CadreUser",
    "elastic_url": "http://127.0.0.1:9200",
    "kibana_url": "http://127.0.0.1:5601",
}

orchestrateur = OrchestrateurCADRE(config)
resultats = orchestrateur.executer_cycle_complet()
print(f"{len(resultats)} attaques auditées")
```
