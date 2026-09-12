# Configuration file for the Sphinx documentation builder.
#
# CADRE — Documentation générée automatiquement
# ===========================================
# Pour builder : cd docs && sphinx-build -b html . _build/html
# Pour live reload : sphinx-autobuild . _build/html
# ===========================================

import sys
from datetime import datetime
from pathlib import Path

# Permettre à Sphinx de trouver le package
sys.path.insert(0, str(Path("../src").resolve()))

# -- Project information -----------------------------------------------------

project = "CADRE"
author = "Mohamed Amine EDDARI"
copyright = f"{datetime.now().year}, {author}"
release = "1.5.0"
version = "1.5"

# -- General configuration ---------------------------------------------------

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",  # Support Google/NumPy docstrings
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinx.ext.coverage",
    "sphinx.ext.githubpages",
    "myst_parser",  # Support Markdown
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "tests"]
language = "fr"

# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
# Pas de html_logo/html_favicon : aucun asset n'existe dans _static/ --
# régression (audit) : les deux lignes pointaient vers des fichiers
# inexistants (logo.png/favicon.ico), Sphinx échouait/avertissait au build.
# À réactiver le jour où de vrais fichiers sont ajoutés dans _static/.

html_theme_options = {
    "collapse_navigation": False,
    "navigation_depth": 4,
    "titles_only": False,
    "prev_next_buttons_location": "bottom",
}

html_context = {
    "display_github": True,
    "github_user": "Mohamed-Amine-Eddari",
    "github_repo": "cadre",
    "github_version": "main",
    "conf_py_path": "/docs/",
}

# -- Options for autodoc -----------------------------------------------------

autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
}

autodoc_typehints = "description"
autodoc_typehints_format = "short"
autoclass_content = "class"

# -- Options for Napoleon (Google docstrings) -------------------------------

napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = False

# -- Options for intersphinx -------------------------------------------------

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "click": ("https://click.palletsprojects.com/", None),
    "rich": ("https://rich.readthedocs.io/en/stable/", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
}

# -- Options for MyST (Markdown) ---------------------------------------------

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "dollarmath",
    "html_image",
    "linkify",
    "replacements",
    "smartquotes",
    "substitution",
    "tasklist",
]
myst_heading_anchors = 3
myst_url_schemes = ["http", "https", "mailto"]
