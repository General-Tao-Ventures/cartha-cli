"""Primary Typer application for the Cartha CLI."""

from __future__ import annotations

import typer

from .config import settings

app = typer.Typer(help="Command line tooling for Cartha subnet miners.")


@app.callback()
def cli_root() -> None:
    """Top-level callback to ensure settings load on startup."""
    typer.echo(f"Using verifier endpoint: {settings.verifier_url}")


@app.command()
def version() -> None:
    """Print the CLI version."""
    from importlib.metadata import version, PackageNotFoundError

    try:
        typer.echo(version("cartha-cli"))
    except PackageNotFoundError:  # pragma: no cover
        typer.echo("0.0.0")


if __name__ == "__main__":  # pragma: no cover
    app()
