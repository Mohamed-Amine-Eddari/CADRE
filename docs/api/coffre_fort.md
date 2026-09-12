# Module `cadre.coffre_fort`

Stockage chiffré des secrets de CADRE (mots de passe VM, identifiants
Elastic/Kibana, secrets de test dédiés) dans un fichier `.env` local
(`~/.cadre/.env`), jamais commité, jamais loggé en clair.

```{eval-rst}
.. automodule:: cadre.coffre_fort
   :members:
   :undoc-members:
   :show-inheritance:
```

## Garde-fous

- Les noms de clés sont validés par un motif strict (`_MOTIF_CLE_SECRET`) —
  refuse tout nom pouvant injecter une nouvelle variable dans le fichier
  `.env` (ex. un saut de ligne dans le nom).
- Toute lecture/écriture/suppression d'un secret est journalisée
  (`SECRET_READ`/`SECRET_WRITE`/`SECRET_DELETE`) — jamais la valeur
  elle-même.

## Exemple

```python
from cadre.coffre_fort import obtenir_coffre

coffre = obtenir_coffre()
coffre.stocker("CADRE_VM_PASS", "motdepasse")
mot_de_passe = coffre.obtenir("CADRE_VM_PASS")
```
