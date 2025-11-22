"""Primary Typer application for the Cartha CLI."""

from __future__ import annotations

import typer

from .commands import (
    claim_deposit,
    miner_password,
    miner_status,
    pair_status,
    prove_lock,
    register,
    version,
)
from .commands.common import log_endpoint_banner, set_trace_enabled
from .commands.help import print_root_help

app = typer.Typer(
    help="Miner-facing tooling for registering on the Cartha subnet, managing pair passwords, and submitting lock proofs.",
    add_completion=False,
)

# Create command groups
miner_app = typer.Typer(
    help="Miner management commands: register, check status, and manage passwords.",
    name="miner",
    invoke_without_command=True,
)
miner_app_alias = typer.Typer(
    help="Miner management commands: register, check status, and manage passwords.",
    name="m",
    invoke_without_command=True,
)
portfolio_app = typer.Typer(
    help="Portfolio management commands: lock funds and claim deposits.",
    name="portfolio",
    invoke_without_command=True,
)
portfolio_app_alias = typer.Typer(
    help="Portfolio management commands: lock funds and claim deposits.",
    name="p",
    invoke_without_command=True,
)


# Define callbacks for groups (show help when invoked without subcommand)
def miner_group_callback(
    ctx: typer.Context,
    help_option: bool = typer.Option(
        False,
        "--help",
        "-h",
        help="Show this message and exit.",
        is_eager=True,
    ),
) -> None:
    """Miner management commands."""
    if ctx.invoked_subcommand is None or help_option:
        ctx.get_help()
        raise typer.Exit()


def portfolio_group_callback(
    ctx: typer.Context,
    help_option: bool = typer.Option(
        False,
        "--help",
        "-h",
        help="Show this message and exit.",
        is_eager=True,
    ),
) -> None:
    """Portfolio management commands."""
    if ctx.invoked_subcommand is None or help_option:
        ctx.get_help()
        raise typer.Exit()


# Register callbacks for both miner apps (main and alias)
miner_app.callback(invoke_without_command=True)(miner_group_callback)
miner_app_alias.callback(invoke_without_command=True)(miner_group_callback)

# Register callbacks for both portfolio apps (main and alias)
portfolio_app.callback(invoke_without_command=True)(portfolio_group_callback)
portfolio_app_alias.callback(invoke_without_command=True)(portfolio_group_callback)

# Register commands in both miner apps (main and alias)
for miner_group in [miner_app, miner_app_alias]:
    miner_group.command("status")(miner_status.miner_status)
    miner_group.command("password")(miner_password.miner_password)
    miner_group.command("register")(register.register)

# Register commands in both portfolio apps (main and alias)
for portfolio_group in [portfolio_app, portfolio_app_alias]:
    portfolio_group.command("lock")(prove_lock.prove_lock)
    portfolio_group.command("claim")(claim_deposit.claim_deposit)

# Add groups with short aliases (after callbacks and commands are registered)
app.add_typer(miner_app, name="miner")
app.add_typer(miner_app_alias, name="m")  # Short alias
app.add_typer(portfolio_app, name="portfolio")
app.add_typer(portfolio_app_alias, name="p")  # Short alias

# Keep pair_app for backward compatibility (deprecated)
pair_app = typer.Typer(
    help="Pair status commands (deprecated - use 'cartha miner status')."
)
app.add_typer(pair_app, name="pair")


@app.callback(invoke_without_command=True)
def cli_root(
    ctx: typer.Context,
    help_option: bool = typer.Option(
        False,
        "--help",
        "-h",
        help="Show this message and exit.",
        is_eager=True,
    ),
    trace: bool = typer.Option(
        False,
        "--trace",
        help="Show full stack traces when errors occur.",
    ),
) -> None:
    """Top-level callback to provide rich help and endpoint banner."""
    set_trace_enabled(trace)
    if ctx.obj is None:
        ctx.obj = {}
    ctx.obj["trace"] = trace

    if help_option:
        print_root_help()
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        print_root_help()
        raise typer.Exit()

    log_endpoint_banner()


# Register top-level commands
app.command("version")(version.version_command)


def help_command() -> None:
    """Show help message."""
    print_root_help()
    raise typer.Exit()


app.command("help")(help_command)

# Keep deprecated commands for backward compatibility
pair_app.command("status")(pair_status.pair_status)


if __name__ == "__main__":  # pragma: no cover
    app()
