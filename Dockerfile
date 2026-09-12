# ===========================================
# CADRE — Dockerfile
# ===========================================
# Image Python 3.13 slim pour l'orchestrateur
# Multi-stage build pour réduire la taille
# Utilisateur non-root pour la sécurité
# ===========================================

# ===========================================
# Stage 1 : Builder (installation des deps)
# ===========================================
FROM python:3.13-slim AS builder

LABEL maintainer="Mohamed Amine EDDARI <eddarimedamine@gmail.com>"
LABEL description="CADRE — Continuous Adversary-Driven Rule Engineering"
LABEL version="1.0.0"
LABEL license="AGPL-3.0"
LABEL org.opencontainers.image.source="https://github.com/Mohamed-Amine-Eddari/cadre"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.title="CADRE"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Installer les outils de build (nécessaires pour certaines wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copier et installer les dépendances
COPY requirements.txt ./
RUN pip install --user --no-cache-dir -r requirements.txt

# Copier le code source
COPY src/ ./src/
COPY pyproject.toml ./

# Installer le package
RUN pip install --user --no-cache-dir .

# ===========================================
# Stage 2 : Runtime (image finale légère)
# ===========================================
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/cadre/.local/bin:${PATH}" \
    CADRE_HOME=/home/cadre/.cadre

# Installer uniquement les libs runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Créer l'utilisateur non-root
RUN groupadd --system --gid 1000 cadre \
    && useradd --system --uid 1000 --gid cadre \
       --home-dir /home/cadre --shell /bin/bash \
       --comment "CADRE orchestrator" cadre

# Copier les packages Python depuis le builder
COPY --from=builder --chown=cadre:cadre /root/.local /home/cadre/.local
COPY --from=builder --chown=cadre:cadre /build/src /app/src

# Répertoires de travail
WORKDIR /app
RUN mkdir -p /app/logs /app/rapports /home/cadre/.cadre \
    && chown -R cadre:cadre /app /home/cadre

# Switcher vers l'utilisateur non-root
USER cadre

# Volumes pour persistance
VOLUME ["/app/logs", "/app/rapports", "/home/cadre/.cadre"]

# Healthcheck : vérifie que l'import fonctionne
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import cadre; from cadre.catalogue_attaques import CATALOGUE; print(f'OK - {len(CATALOGUE)} attaques')" \
    || exit 1

# tini pour une bonne gestion des signaux (PID 1)
ENTRYPOINT ["/usr/bin/tini", "--"]

# Commande par défaut : afficher l'aide
CMD ["cadre", "--help"]
