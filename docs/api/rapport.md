# Module `cadre.rapport`

Génère les livrables d'un cycle d'audit : rapport Markdown, export CSV
(Excel/LibreOffice), rapport HTML interactif autonome, layer MITRE ATT&CK
Navigator (JSON), et le rapport de soutenance PFA.

```{eval-rst}
.. automodule:: cadre.rapport
   :members:
   :undoc-members:
   :show-inheritance:
```

## Défense contre l'injection de formule CSV

`generer_csv` neutralise (`_defuse_formule_csv`) toute valeur de cellule
commençant par `=`, `+`, `-`, `@`, une tabulation ou un retour chariot —
sans quoi Excel/LibreOffice l'interpréterait comme une formule active à
l'ouverture (CWE-1236), un risque réel dès qu'un champ comme `description`
ou `raison` peut provenir d'une attaque personnelle ou d'un brouillon
généré par IA.

## Exemple

```python
from cadre.rapport import generer_rapport_cycle, generer_csv

generer_rapport_cycle(resultats_cycle, Path("rapports/cycle.md"))
generer_csv(resultats_cycle, Path("rapports/cycle.csv"))
```
