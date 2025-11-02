"""Cartha CLI package."""

def main() -> None:  # pragma: no cover
    from .main import app

    app()


__all__ = ["main"]
