# Copyright (C) 2026 Mohamed Amine EDDARI <eddarimedamine@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of CADRE. Full license text: LICENSE (repository root).

"""
CADRE — Coffre-fort pour credentials
====================================

Gestion sécurisée des secrets utilisés par CADRE. Supporte :
- Variables d'environnement (développement)
- Fichier .env avec python-dotenv
- Coffre-fort Windows Credential Manager (production)
- Chiffrement AES-128 (Fernet) pour stockage local

INTERDIT : Aucun secret ne doit jamais apparaître en clair dans le code source.
INTERDIT : Aucun secret ne doit être commité dans Git (vérifié par pre-commit hook).
"""

from __future__ import annotations

import contextlib
import os
import re
from pathlib import Path

from cadre.logger import obtenir_logger

# Tentative d'import des dépendances optionnelles
try:
    from cryptography.fernet import Fernet

    CRYPTO_DISPONIBLE = True
except ImportError:
    CRYPTO_DISPONIBLE = False

try:
    from dotenv import load_dotenv, set_key, unset_key

    DOTENV_DISPONIBLE = True
except ImportError:
    DOTENV_DISPONIBLE = False

try:
    import keyring

    KEYRING_DISPONIBLE = True
except ImportError:
    KEYRING_DISPONIBLE = False


CHEMIN_COFFRE = Path.home() / ".cadre"
FICHIER_ENV = CHEMIN_COFFRE / ".env"
FICHIER_MASTER_KEY = CHEMIN_COFFRE / "master.key"

# Nom de secret valide : convention env var classique (MAJUSCULES, chiffres,
# '_', débute par une lettre). Appliqué dans stocker() -- voir son docstring
# pour la raison (injection via set_key() du repli .env).
_MOTIF_CLE_SECRET = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


class ErreurSecurite(Exception):
    """Erreur liée à la gestion des secrets."""

    pass


def _generer_cle_maitre() -> bytes:
    """Génère une clé Fernet et la stocke avec permissions restrictives."""
    if not CRYPTO_DISPONIBLE:
        raise ErreurSecurite(
            "Le module 'cryptography' est requis. " "Installez-le : pip install cryptography"
        )
    CHEMIN_COFFRE.mkdir(parents=True, exist_ok=True, mode=0o700)
    cle = Fernet.generate_key()
    FICHIER_MASTER_KEY.write_bytes(cle)
    with contextlib.suppress(OSError, AttributeError):
        FICHIER_MASTER_KEY.chmod(0o600)  # Windows ne supporte pas tous les modes POSIX
    return cle


def _charger_cle_maitre() -> bytes:
    """Charge la clé maître ou la génère si absente."""
    if FICHIER_MASTER_KEY.exists():
        return FICHIER_MASTER_KEY.read_bytes()
    return _generer_cle_maitre()


# Préfixe distinctif des valeurs chiffrées dans le fichier .env -- permet une
# migration douce : une valeur SANS ce préfixe est soit un secret en clair
# d'une installation antérieure à ce correctif, soit une vraie variable
# d'environnement externe (CI/CD, conteneur) jamais chiffrée par CADRE --
# dans les deux cas, elle ne doit JAMAIS être altérée ni provoquer d'erreur.
_PREFIXE_CHIFFRE = "cadre-enc:"


def _chiffrer_pour_env(valeur: str) -> str:
    """Chiffre une valeur avant écriture dans le fichier .env (repli utilisé
    quand le coffre système/keyring est indisponible). Sans ce chiffrement,
    tout secret stocké via ce repli finissait en clair sur disque -- seul
    rempart un `chmod(0o600)` qui ne restreint pas réellement l'accès sous
    Windows (voir `_generer_cle_maitre`), alors que le docstring du module
    annonce explicitement ce chiffrement comme garantie de sécurité."""
    fernet = Fernet(_charger_cle_maitre())
    return _PREFIXE_CHIFFRE + fernet.encrypt(valeur.encode("utf-8")).decode("ascii")


def _dechiffrer_si_besoin(valeur: str) -> str:
    """Déchiffre `valeur` SI elle porte le préfixe de chiffrement CADRE ;
    la retourne inchangée sinon (secret en clair hérité, ou vraie variable
    d'environnement externe -- jamais chiffrée par CADRE)."""
    if not valeur.startswith(_PREFIXE_CHIFFRE):
        return valeur
    jeton = valeur[len(_PREFIXE_CHIFFRE) :]
    try:
        fernet = Fernet(_charger_cle_maitre())
        return fernet.decrypt(jeton.encode("ascii")).decode("utf-8")
    except Exception as e:
        raise ErreurSecurite(
            f"Secret chiffré illisible (clé maître manquante ou différente) : {FICHIER_MASTER_KEY}"
        ) from e


class CoffreFortCADRE:
    """
    Gestionnaire centralisé des credentials CADRE.

    Ordre de priorité pour la lecture d'un secret :
    1. Variable d'environnement (CI/CD, conteneurs)
    2. Coffre système (Windows Credential Manager, macOS Keychain, Linux Secret Service)
    3. Fichier .env local (développement uniquement)

    Ordre de priorité pour l'écriture :
    1. Coffre système (production)
    2. Fichier .env avec permissions restrictives (fallback)
    """

    NOM_SERVICE = "CADRE_PurpleTeam"

    def __init__(self, utiliser_keychain: bool = True):
        self.utiliser_keychain = utiliser_keychain and KEYRING_DISPONIBLE
        CHEMIN_COFFRE.mkdir(parents=True, exist_ok=True, mode=0o700)
        if DOTENV_DISPONIBLE and FICHIER_ENV.exists():
            load_dotenv(FICHIER_ENV, override=False)

    @staticmethod
    def _journaliser_acces(type_evt: str, cle: str, **kwargs: object) -> None:
        """Trace d'audit d'un accès au coffre-fort — jamais la valeur du secret.

        La LECTURE d'un secret est journalisée en DEBUG : elle reste dans le
        fichier d'audit JSON (trace forensic complète) mais n'inonde pas la
        console — le dashboard relit les secrets à chaque sondage (~5 s), ce qui
        produisait un flot de lignes illisible. L'ÉCRITURE/SUPPRESSION (rare
        et sensible) reste en INFO/visible ; un échec reste en WARN.
        """
        echec = kwargs.get("trouve") is False or kwargs.get("supprime") is False
        if echec:
            niveau = "WARN"
        elif type_evt == "SECRET_READ":
            niveau = "DEBUG"
        else:
            niveau = "INFO"
        message = f"Coffre-fort : {type_evt} '{cle}'"
        obtenir_logger().evenement(type_evt, message, niveau, cle=cle, **kwargs)

    def obtenir(self, cle: str, defaut: str | None = None) -> str | None:
        """
        Récupère un secret. Cherche dans l'ordre : env > keychain > .env.
        Lève ErreurSecurite si non trouvé et pas de défaut.

        Chaque accès est journalisé (clé + source), jamais la valeur.
        """
        # 1. Variable d'environnement (toujours prioritaire). Déchiffre SI la
        # valeur porte le préfixe CADRE -- déjà chargée depuis .env par
        # __init__ (load_dotenv) ou un appel précédent à cette méthode ; une
        # vraie variable d'environnement externe n'a jamais ce préfixe et
        # n'est donc jamais touchée par _dechiffrer_si_besoin.
        valeur = os.environ.get(cle)
        if valeur:
            if CRYPTO_DISPONIBLE:
                valeur = _dechiffrer_si_besoin(valeur)
            self._journaliser_acces("SECRET_READ", cle, source="env")
            return valeur

        # 2. Coffre système (keyring) -- déjà chiffré par l'OS (Windows
        # Credential Manager/Keychain/Secret Service), pas de double chiffrement.
        if self.utiliser_keychain:
            try:
                valeur = keyring.get_password(self.NOM_SERVICE, cle)
                if valeur:
                    self._journaliser_acces("SECRET_READ", cle, source="keychain")
                    return valeur
            except Exception:  # nosec B110 - keyring optionnel (peut être absent en CI)
                pass

        # 3. Fichier .env
        if DOTENV_DISPONIBLE:
            load_dotenv(FICHIER_ENV, override=False)
            valeur = os.environ.get(cle)
            if valeur:
                if CRYPTO_DISPONIBLE:
                    valeur = _dechiffrer_si_besoin(valeur)
                self._journaliser_acces("SECRET_READ", cle, source="dotenv")
                return valeur

        if defaut is not None:
            self._journaliser_acces("SECRET_READ", cle, source="defaut")
            return defaut

        self._journaliser_acces("SECRET_READ", cle, source=None, trouve=False)
        raise ErreurSecurite(
            f"Secret '{cle}' introuvable. "
            f"Définissez-le via : export {cle}=...  ou  cadre init --set {cle}=..."
        )

    def stocker(self, cle: str, valeur: str, methode: str = "auto") -> None:
        """
        Stocke un secret de manière sécurisée.

        Args:
            cle: Nom du secret
            valeur: Valeur à stocker (ne sera JAMAIS loggée)
            methode: "keychain", "env" ou "auto"

        Régression sécurité : `cle` n'était jamais validée -- le repli .env
        (`methode="env"`) écrit `cle` BRUTE via `dotenv.set_key()`, qui ne
        neutralise pas un saut de ligne (vérifié empiriquement : une clé
        `"FOO\\nCADRE_ELASTIC_URL=http://attaquant/"` injecte réellement
        une seconde ligne dans `~/.cadre/.env`, une variable arbitraire au
        prochain `load_dotenv()`). Seule `valeur` était quotée par dotenv,
        jamais `cle`. Rejetée AVANT toute écriture, quelle que soit `methode`
        (y compris keychain, par cohérence -- même si ce risque précis est
        propre au repli fichier).
        """
        if not valeur or not isinstance(valeur, str):
            raise ErreurSecurite("La valeur du secret doit être une chaîne non vide.")
        if not isinstance(cle, str) or not _MOTIF_CLE_SECRET.fullmatch(cle):
            raise ErreurSecurite(
                "Nom de secret invalide -- lettres majuscules, chiffres et '_' "
                "uniquement, débutant par une lettre (ex. CADRE_MA_CLE)."
            )

        if methode == "auto":
            methode = "keychain" if self.utiliser_keychain else "env"

        if methode == "keychain":
            if not self.utiliser_keychain:
                raise ErreurSecurite(
                    "Le module 'keyring' n'est pas disponible. "
                    "Utilisez methode='env' ou installez : pip install keyring"
                )
            keyring.set_password(self.NOM_SERVICE, cle, valeur)
        elif methode == "env":
            CHEMIN_COFFRE.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not DOTENV_DISPONIBLE:
                raise ErreurSecurite(
                    "Le module 'python-dotenv' est requis. "
                    "Installez-le : pip install python-dotenv"
                )
            # Chiffré avant écriture (Fernet) -- `cryptography` est une
            # dépendance obligatoire de CADRE (pyproject.toml), pas
            # optionnelle : ce repli ne doit jamais stocker un secret en
            # clair sur disque, conformément à l'INTERDIT du docstring du
            # module. _chiffrer_pour_env lève ErreurSecurite (via
            # _charger_cle_maitre) si 'cryptography' est malgré tout absent.
            set_key(str(FICHIER_ENV), cle, _chiffrer_pour_env(valeur))
            with contextlib.suppress(OSError, AttributeError):
                FICHIER_ENV.chmod(0o600)
        else:
            raise ErreurSecurite(f"Méthode inconnue : {methode}")

        self._journaliser_acces("SECRET_WRITE", cle, methode=methode)

    def supprimer(self, cle: str) -> bool:
        """Supprime un secret du coffre. Retourne True si supprimé."""
        supprime = False
        if self.utiliser_keychain:
            try:
                keyring.delete_password(self.NOM_SERVICE, cle)
                supprime = True
            except Exception:  # nosec B110 - suppression keyring best-effort
                pass
        if DOTENV_DISPONIBLE and FICHIER_ENV.exists():
            retire, _ = unset_key(str(FICHIER_ENV), cle)
            supprime = supprime or bool(retire)
        self._journaliser_acces("SECRET_DELETE", cle, supprime=supprime)
        return supprime

    def lister_cles(self) -> list[str]:
        """
        Liste les noms des secrets CADRE configurés (PAS les valeurs).

        Ne filtre que les variables d'environnement préfixées `CADRE_` —
        `os.environ` contient des centaines de variables système
        (PATH, USERNAME, variables d'IDE...) sans rapport avec les
        secrets de l'outil ; les inclure toutes serait une fuite
        d'information, pas une fonctionnalité (constaté en exposant cette
        méthode via le dashboard web : la liste complète de l'environnement
        système apparaissait dans la réponse).
        """
        cles: set[str] = {c for c in os.environ if c.startswith("CADRE_")}
        if DOTENV_DISPONIBLE and FICHIER_ENV.exists():
            with FICHIER_ENV.open() as f:
                for ligne_brute in f:
                    ligne = ligne_brute.strip()
                    if ligne and not ligne.startswith("#") and "=" in ligne:
                        cles.add(ligne.split("=", 1)[0])
        return sorted(cles)


# Instance singleton
_coffre_instance: CoffreFortCADRE | None = None


def obtenir_coffre() -> CoffreFortCADRE:
    """Retourne l'instance singleton du coffre-fort."""
    global _coffre_instance
    if _coffre_instance is None:
        _coffre_instance = CoffreFortCADRE()
    return _coffre_instance


def secret_or_none(cle: str) -> str | None:
    """Helper : retourne le secret ou None sans exception."""
    try:
        return obtenir_coffre().obtenir(cle)
    except ErreurSecurite:
        return None


if __name__ == "__main__":
    # Test rapide
    coffre = CoffreFortCADRE()
    print(f"Coffre-fort CADRE — répertoire : {CHEMIN_COFFRE}")
    print(f"Cryptography dispo : {CRYPTO_DISPONIBLE}")
    print(f"Dotenv dispo       : {DOTENV_DISPONIBLE}")
    print(f"Keyring dispo      : {KEYRING_DISPONIBLE}")
    print(f"Clés configurées   : {coffre.lister_cles()}")
