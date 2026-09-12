# Guide de contribution

> Merci de votre intérêt pour CADRE !
> Ce document explique comment contribuer efficacement au projet.

## Code de conduite

Ce projet adhère à un [code de conduite](CODE_OF_CONDUCT.md). En participant,
vous vous engagez à le respecter. Soyez respectueux, constructif, et
professionnel.

## Comment contribuer ?

### Signaler un bug

1. Vérifiez que le bug n'a pas déjà été signalé dans les [issues](https://github.com/Mohamed-Amine-Eddari/cadre/issues)
2. Ouvrez une nouvelle issue avec le label `bug`
3. Incluez :
   - Version de CADRE (`cadre --version`)
   - OS et version (Windows 10/11, Ubuntu 22.04, etc.)
   - Version de Python (`python --version`)
   - Étapes de reproduction
   - Comportement attendu vs observé
   - Logs pertinents (`logs/cadre.log.json`)

### Proposer une fonctionnalité

1. Ouvrez une issue avec le label `enhancement`
2. Décrivez :
   - Le besoin métier
   - L'API souhaitée (exemple de code si possible)
   - Les alternatives envisagées
   - L'impact sur la compatibilité

### Soumettre une Pull Request

#### 1. Fork & clone

```bash
# Fork via GitHub UI, puis :
git clone https://github.com/VOTRE_USER/cadre.git
cd cadre
git remote add upstream https://github.com/Mohamed-Amine-Eddari/cadre.git
```

#### 2. Créer une branche

```bash
git checkout -b feature/ma-nouvelle-fonctionnalite
# ou
git checkout -b fix/mon-bug
```

Convention de nommage :
- `feature/<nom-kebab-case>` pour les nouvelles fonctionnalités
- `fix/<nom-kebab-case>` pour les corrections
- `docs/<nom-kebab-case>` pour la doc seule
- `refactor/<nom-kebab-case>` pour les refactorings
- `test/<nom-kebab-case>` pour les tests

#### 3. Développer

##### Standards de code

```bash
# Formatage automatique
black src/ tests/

# Lint
ruff check src/ tests/

# Vérification des types (optionnel mais recommandé)
mypy src/cadre/
```

##### Conventions Python

- **Python 3.11+** requis (utilisation de `match`, `|`, `dict[str, int]`, etc.)
- **Type hints** obligatoires sur toutes les fonctions publiques
- **Docstrings** au format Google
- **Frozen dataclasses** pour les structures de données immuables
- **Pathlib** plutôt que `os.path`
- **f-strings** plutôt que `.format()` ou `%`
- **Logging** via le module `cadre.logger`, jamais `print()`

##### Exemple de code

```python
"""Module de démonstration pour les contributeurs."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResultatAudit:
    """Résultat d'un audit unitaire."""
    identifiant: str
    succes: bool
    message: str


def analyser_audit(chemin: Path) -> ResultatAudit:
    """Analyse un rapport d'audit.

    Args:
        chemin: Chemin vers le rapport Markdown.

    Returns:
        Le résultat de l'analyse.

    Raises:
        FileNotFoundError: Si le fichier n'existe pas.
    """
    if not chemin.exists():
        logger.error("Rapport introuvable : %s", chemin)
        raise FileNotFoundError(f"Fichier absent : {chemin}")

    contenu = chemin.read_text(encoding="utf-8")
    succes = "VALIDE" in contenu
    message = "OK" if succes else "Aucun résultat VALIDE"

    return ResultatAudit(
        identifiant=chemin.stem,
        succes=succes,
        message=message,
    )
```

#### 4. Tests

**Tout nouveau code doit être accompagné de tests.**

```bash
# Lancer les tests
pytest tests/ -v

# Avec couverture
pytest tests/ --cov=cadre --cov-report=term-missing

# Minimum de couverture : 75%
```

##### Structure des tests

```python
# tests/test_mon_module.py

import pytest
from cadre.mon_module import ma_fonction


class TestMaFonction:
    """Tests de ma_fonction()."""

    def test_cas_nominal(self):
        """Comportement attendu sur entrée valide."""
        resultat = ma_fonction("entrée")
        assert resultat == "sortie"

    def test_cas_erreur(self):
        """Comportement attendu sur entrée invalide."""
        with pytest.raises(ValueError, match="invalide"):
            ma_fonction("")

    @pytest.mark.parametrize("entree,sortie", [
        ("a", "A"),
        ("b", "B"),
        ("c", "C"),
    ])
    def test_parametres(self, entree, sortie):
        """Tests paramétrés."""
        assert ma_fonction(entree) == sortie
```

#### 5. Documentation

Si votre PR modifie le comportement utilisateur :

- Mettre à jour le `README.md`
- Ajouter une entrée dans le `CHANGELOG.md` (section "Unreleased")
- Compléter la docstring
- Si nouveau module : ajouter une section dans `docs/ARCHITECTURE.md`

#### 6. Commit & push

```bash
# Vérifications avant commit
black src/ tests/
ruff check src/ tests/
pytest tests/ -v
bandit -r src/

# Commit (Conventional Commits)
git add .
git commit -m "feat(catalogue): ajout de la technique T1053.005"

# Push
git push origin feature/ma-nouvelle-fonctionnalite
```

##### Format des commits (Conventional Commits)

| Préfixe | Usage |
|---------|-------|
| `feat:` | Nouvelle fonctionnalité |
| `fix:` | Correction de bug |
| `docs:` | Documentation seule |
| `style:` | Formatage (pas de changement de code) |
| `refactor:` | Refactoring (ni fix ni feature) |
| `test:` | Ajout de tests |
| `chore:` | Maintenance (deps, config, etc.) |
| `security:` | Correction de vulnérabilité |

Exemples :

```bash
git commit -m "feat: ajout de l'anonymisation des NTLM hashes"
git commit -m "fix(winrm): timeout sur les VM lentes"
git commit -m "docs: mise à jour du modèle de menace"
git commit -m "security: mise à jour cryptography>=41.0.0 (CVE-2023-50782)"
```

#### 7. Pull Request

1. Pushez votre branche
2. Ouvrez une PR sur GitHub
3. Remplissez le template :

```markdown
## Description
Brève description de la modification.

## Type de changement
- [ ] Bug fix (non-breaking)
- [ ] Nouvelle fonctionnalité (non-breaking)
- [ ] Breaking change (corrige ou feature qui casse la compat)
- [ ] Documentation

## Tests
- [ ] Tests unitaires ajoutés
- [ ] Tests existants passent
- [ ] Couverture maintenue (≥ 75%)

## Checklist
- [ ] Code formatté (black)
- [ ] Lint passé (ruff)
- [ ] Type hints vérifiés (mypy)
- [ ] Documentation à jour
- [ ] CHANGELOG.md mis à jour
```

4. Attendez la review

## Ajouter une attaque au catalogue

C'est la contribution la plus fréquente. Voici la procédure complète :

### 1. Rechercher la technique

- Allez sur [MITRE ATT&CK](https://attack.mitre.org/)
- Identifiez la technique et la sous-technique (ex: T1003.002)
- Notez :
  - L'ID et le nom
  - La tactique parente
  - Les EventIDs Windows qui la détectent
  - Les faux positifs connus
  - Les références (URLs Atomic Red Team, etc.)

### 2. Tester en local

Exécutez la commande sur votre VM cible **manuellement** et vérifiez
qu'elle génère bien l'EventID attendu.

### 3. Ajouter au catalogue

Éditez `src/cadre/catalogue_attaques.py` :

```python
AttaqueCatalogue(
    id="CADRE-CAT-013",  # ID unique suivant la nomenclature
    nom="Votre technique",
    description="Description lisible de la technique",
    technique_mitre="T1234.567",
    tactique_mitre="Tactique",
    sous_technique="Sous-technique",
    commande="commande PowerShell à exécuter",
    event_ids_attendus=["4624", "4688"],
    champ_principal="process.command_line",
    faux_positifs_connus=[
        "process.exe --known-arg",  # Pattern à ignorer
    ],
    niveau_risque=NiveauRisque.MOYEN,
    plateforme=Plateforme.WINDOWS,
    references=[
        "https://attack.mitre.org/techniques/T1234/567/",
    ],
    prerequisites=["Sysmon installé", "Winlogbeat configuré"],
    duree_estimee_sec=5,
),
```

### 4. Ajouter les tests

Éditez `tests/test_catalogue.py` :

```python
def test_attaque_cadre_cat_013(self):
    """Test de l'attaque CADRE-CAT-013."""
    from cadre.catalogue_attaques import obtenir_attaque
    attaque = obtenir_attaque("CADRE-CAT-013")
    assert attaque is not None
    assert attaque.technique_mitre == "T1234.567"
    assert "4688" in attaque.event_ids_attendus
```

### 5. Documenter

- Ajouter une ligne dans le tableau du `WHITE_PAPER.md`
- Ajouter une ligne dans le tableau du `README.md`
- Ajouter une section dans `docs/ARCHITECTURE.md`

### 6. Soumettre la PR

Suivez le processus standard.

## Ajouter un module transversal

Exemple : `rapport.py`, `anonymisation.py`, etc.

1. Créer le fichier dans `src/cadre/`
2. Ajouter les tests dans `tests/`
3. Documenter dans `docs/ARCHITECTURE.md`
4. Ajouter à l'API publique dans `src/cadre/__init__.py` si pertinent
5. Soumettre la PR

## Release

Le processus de release est automatisé via GitHub Actions :

1. Mettre à jour la version dans `src/cadre/__init__.py` et `pyproject.toml`
2. Mettre à jour `CHANGELOG.md` (déplacer "Unreleased" vers versionnée)
3. Créer un tag : `git tag -a v1.0.0 -m "Release 1.0.0"`
4. Pousser le tag : `git push upstream v1.0.0`
5. La CI build et publie automatiquement sur PyPI

## Questions ?

- [Discussions GitHub](https://github.com/Mohamed-Amine-Eddari/cadre/discussions)
- [Issues](https://github.com/Mohamed-Amine-Eddari/cadre/issues)
- eddarimedamine@gmail.com

Merci pour votre contribution !
