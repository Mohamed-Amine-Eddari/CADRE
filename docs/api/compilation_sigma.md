# Module `cadre.compilation_sigma`

Compile une règle Sigma (YAML) vers une requête Lucene (via `pySigma`), puis
mesure son comportement réel contre Elasticsearch : double validation vrais
positifs / faux positifs (`double_validation_tp_fp`) avant tout déploiement
dans Kibana.

```{eval-rst}
.. automodule:: cadre.compilation_sigma
   :members:
   :undoc-members:
   :show-inheritance:
```

## Fail-closed sur panne Elasticsearch

Une mesure TP/FP qui échoue (Elasticsearch injoignable, timeout, erreur
HTTP) lève `ErreurComptageElastic` (voir `cadre.attente_indexation`) plutôt
que de retourner silencieusement `0` — une panne pendant la mesure ne doit
jamais se lire comme « zéro faux positif », ce qui validerait une règle
sans aucune preuve réelle.

## Exemple

```python
from cadre.compilation_sigma import compiler_sigma_vers_lucene, double_validation_tp_fp

requete_lucene = compiler_sigma_vers_lucene(regle_sigma_yaml)
```
