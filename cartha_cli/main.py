"""Primary Typer application for the Cartha CLI."""

from __future__ import annotations

import typer

from .bt import RegistrationResult, register_hotkey
from .config import settings

app = typer.Typer(help="Command line tooling for Cartha subnet miners.")
subnet_app = typer.Typer(help="Subnet management commands.")


app.add_typer(subnet_app, name="s")


@app.callback()
def cli_root() -> None:
    """Top-level callback to ensure settings load on startup."""
    if settings.verifier_url.startswith("http://127.0.0.1"):
        typer.echo(f"Using local verifier endpoint: {settings.verifier_url}")
    else:
        typer.echo("Using configured verifier endpoint: Cartha")


@app.command()
def version() -> None:
    """Print the CLI version."""
    from importlib.metadata import version, PackageNotFoundError

    try:
        typer.echo(version("cartha-cli"))
    except PackageNotFoundError:  # pragma: no cover
        typer.echo("0.0.0")


@subnet_app.command("register")
def subnet_register(
    
    network: str = typer.Option(settings.network, "--network", help="Bittensor network name."),
    wallet_name: str = typer.Option(
        ..., "--wallet-name", "--wallet.name", help="Coldkey wallet name."
    ),
    wallet_hotkey: str = typer.Option(
        ..., "--wallet-hotkey", "--wallet.hotkey", help="Hotkey name."
    ),
    netuid: int = typer.Option(settings.netuid, "--netuid", help="Subnet netuid."),
    burned: bool = typer.Option(
        True,
        "--burned/--pow",
        help="Burned registration by default; pass --pow to run PoW registration.",
    ),
    cuda: bool = typer.Option(False, "--cuda", help="Enable CUDA for PoW registration."),
) -> None:
    """Register the specified hotkey on the target subnet and print the UID."""

    typer.echo(f"Registering hotkey '{wallet_hotkey}' on netuid {netuid} (network={network})")

    result: RegistrationResult = register_hotkey(
        network=network,
        wallet_name=wallet_name,
        hotkey_name=wallet_hotkey,
        netuid=netuid,
        burned=burned,
        cuda=cuda,
    )

    if result.status == "already":
        typer.echo(f"Hotkey already registered. UID: {result.uid}")
        return

    if not result.success:
        typer.secho("Registration failed.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if result.status == "burned":
        typer.echo("Burned registration success.")
    else:
        typer.echo("Registration success.")

    if result.uid is not None:
        typer.echo(f"Registered uid: {result.uid}")
    else:
        typer.echo("Warning: UID not yet available (node may still be syncing).")


if __name__ == "__main__":  # pragma: no cover
    app()
