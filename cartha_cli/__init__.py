"""Cartha CLI package."""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("cartha-cli")
except PackageNotFoundError:  # pragma: no cover - during local dev
    __version__ = "0.0.0"

__all__ = ["__version__"]
