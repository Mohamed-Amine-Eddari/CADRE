# Module `cadre.anonymisation`

Anonymise les logs Elastic collectés (noms d'utilisateur, domaine, IP,
e-mail) avant qu'ils ne servent à générer une règle Sigma ou à alimenter un
rapport — par hachage déterministe salé, jamais par suppression pure (un
même utilisateur produit toujours le même haché, ce qui préserve la
capacité à corréler plusieurs événements du même acteur sans exposer son
identité réelle).

```{eval-rst}
.. automodule:: cadre.anonymisation
   :members:
   :undoc-members:
   :show-inheritance:
```

## Exemple

```python
from cadre.anonymisation import anonymiser_log_elastic

log_anonymise = anonymiser_log_elastic(log_elastic_brut)
```
