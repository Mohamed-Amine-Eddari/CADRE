# CADRE — Makefile
# ===========================================
# Simplifie les tâches courantes de développement
# ===========================================

.PHONY: help install install-dev test test-cov test-security lint format type-check \
        security docs docs-serve clean run cycle status init build publish docker-build \
        docker-run docker-stop pre-commit all ci

.DEFAULT_GOAL := help

# === COULEURS ===
GREEN  := \033[0;32m
YELLOW := \033[0;33m
BLUE   := \033[0;34m
RESET  := \033[0m

# === AIDE ===
help: ## Afficher cette aide
	@echo "$(GREEN)CADRE — Commandes disponibles$(RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	    awk 'BEGIN {FS = ":.*?## "}; {printf "$(YELLOW)%-20s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# === INSTALLATION ===
install: ## Installer le package en mode production
	pip install -r requirements.txt
	pip install -e .

install-dev: ## Installer avec les dépendances de dev
	pip install -r requirements-dev.txt
	pip install -e .

# === TESTS ===
test: ## Lancer les tests unitaires
	pytest tests/ -v

test-cov: ## Tests avec couverture de code
	pytest tests/ -v --cov=cadre --cov-report=html --cov-report=term-missing --cov-fail-under=75

test-security: ## Lancer les tests de sécurité
	pytest tests/test_securite.py -v

test-fast: ## Tests rapides uniquement (exclut slow et integration)
	pytest tests/ -v -m "not slow and not integration"

# === QUALITÉ DE CODE ===
lint: ## Vérifier le linting (ruff + black --check)
	ruff check src/ tests/
	black --check --diff src/ tests/

format: ## Formater le code (black + isort)
	black src/ tests/
	isort src/ tests/
	ruff check --fix src/ tests/

type-check: ## Vérifier les types (mypy)
	mypy src/cadre/

# === SÉCURITÉ ===
# Régression (audit) : --severity-level/--confidence-level medium filtrait
# les findings LOW ici alors que la vraie CI (bandit -r src -q, sans aucun
# filtre) et `make ci` les font échouer -- exactement la même classe d'écart
# déjà corrigée dans .pre-commit-config.yaml (voir son commentaire). Retiré
# pour que `make security` ne puisse plus afficher "sûr" alors que la CI
# bloquerait.
security: ## Audit de sécurité (bandit + pip-audit)
	bandit -r src/ -q
	pip-audit -r requirements.txt --desc --ignore-vuln PYSEC-2026-2447

# === DOCUMENTATION ===
docs: ## Builder la documentation Sphinx
	cd docs && sphinx-build -b html . _build/html

docs-serve: ## Servir la doc en local (live reload)
	cd docs && sphinx-autobuild . _build/html --host 0.0.0.0 --port 8000

docs-clean: ## Nettoyer le build de la doc
	rm -rf docs/_build/

# === EXÉCUTION ===
run: ## Lancer CADRE (équivalent à `cadre`)
	cadre

cycle: ## Lancer un cycle d'audit complet
	cadre cycle

status: ## Vérifier l'état de la stack
	cadre status

init: ## Configurer les secrets (interactif)
	cadre init

# === BUILD & PUBLISH ===
clean: ## Nettoyer les fichiers générés
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/ .coverage htmlcov/ .secrets-scan.json
	rm -rf logs/* rapports/*
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

build: clean ## Construire le package
	python -m build

publish: build ## Publier sur PyPI (dry-run par défaut)
	twine upload --repository testpypi dist/*

publish-prod: build ## Publier sur PyPI production
	twine upload dist/*

# === DOCKER ===
docker-build: ## Builder l'image Docker
	docker build -t mohamedamineeddari/cadre:1.0.0 -t mohamedamineeddari/cadre:latest .

docker-run: ## Lancer l'orchestrateur dans Docker
	docker compose --profile with-orchestrateur up cadre

docker-up: ## Démarrer la stack Elastic
	docker compose up -d

docker-down: ## Arrêter la stack
	docker compose down

docker-logs: ## Voir les logs Docker
	docker compose logs -f

docker-clean: ## Nettoyer les volumes Docker (⚠️ perte de données)
	docker compose down -v

# === PRE-COMMIT ===
pre-commit: ## Installer les hooks pre-commit
	pre-commit install
	pre-commit run --all-files

# === TOUT-EN-UN ===
all: lint type-check test security ## Lint + types + tests + sécurité
	@echo "$(GREEN)✅ Toutes les vérifications sont passées$(RESET)"

# === CI LOCAL (reproduit EXACTEMENT les gates de .github/workflows/cadre-ci.yml) ===
# Régression (audit) : le commentaire ci-dessus affirmait une parité EXACTE
# avec la CI réelle qui n'a jamais été vraie -- 2 gates entières absentes
# (hygiène pre-commit, detect-secrets), et bandit/pip-audit tournaient ici
# avec des filtres/exclusions qui n'existent PAS dans la CI (bandit sans
# --severity-level/--confidence-level, pip-audit sans -r/--ignore-vuln,
# scope complet de l'environnement installé). `make ci` pouvait donc
# afficher "sûr de pousser" alors que la vraie CI aurait échoué sur des
# findings que ces filtres masquaient localement -- exactement l'inverse
# de ce que cette cible promet. Ordre et commandes alignés ligne à ligne
# sur .github/workflows/cadre-ci.yml (hors installation des dépendances,
# déjà couverte par `make install-dev`, et l'upload codecov, sans objet en
# local).
ci: ## Rejoue les gates du CI en local (à lancer AVANT de pousser)
	@echo "$(BLUE)== 1/8 Hygiène du dépôt (pre-commit-hooks) ==$(RESET)"
	pre-commit run trailing-whitespace --all-files
	pre-commit run end-of-file-fixer --all-files
	pre-commit run check-yaml --all-files
	pre-commit run check-json --all-files
	pre-commit run check-toml --all-files
	pre-commit run check-merge-conflict --all-files
	pre-commit run check-added-large-files --all-files
	pre-commit run detect-private-key --all-files
	@echo "$(BLUE)== 2/8 Pytest + couverture (seuil 75%) ==$(RESET)"
	pytest tests/ -q --cov=cadre --cov-report=term-missing --cov-report=xml --cov-fail-under=75
	@echo "$(BLUE)== 3/8 Ruff (lint) ==$(RESET)"
	ruff check src tests
	@echo "$(BLUE)== 4/8 Black (formatage) ==$(RESET)"
	black --check src tests
	@echo "$(BLUE)== 5/8 MyPy (types) ==$(RESET)"
	mypy src/cadre
	@echo "$(BLUE)== 6/8 Sécurité statique (bandit) ==$(RESET)"
	bandit -r src -q
	@echo "$(BLUE)== 7/8 Audit des dépendances (pip-audit, jamais bloquant — voir W6, docs/SECURITY.md) ==$(RESET)"
	-pip-audit
	@echo "$(BLUE)== 8/8 Secrets (detect-secrets) ==$(RESET)"
	@# Fichier local (`.secrets-scan.json`, voir .gitignore/clean), pas
	@# /tmp/ comme dans cadre-ci.yml -- ubuntu-latest garantit /tmp, un
	@# poste de dev Windows/Git Bash non.
	detect-secrets scan > .secrets-scan.json
	python -c "import json,sys; d=json.load(open('.secrets-scan.json')); sys.exit(1 if d.get('results') else 0)"
	@echo "$(GREEN)✅ CI local vert — sûr de pousser$(RESET)"
