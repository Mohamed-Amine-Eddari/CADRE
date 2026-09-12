# Minimal makefile for Sphinx on Windows
# ===========================================

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help %SOURCEDIR% %BUILDDIR% %SPHINXOPTS% %O%

.PHONY: help Makefile

%: Makefile
	@$(SPHINXBUILD) -M %SOURCEDIR% %BUILDDIR% %SPHINXOPTS% %O%
