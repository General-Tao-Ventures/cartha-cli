"""Primary Typer application for the Cartha CLI."""

from __future__ import annotations

import typer

from .commands import (
    claim_deposit,
    extend_lock,
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
pair_app = typer.Typer(help="Pair status commands.")

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


# Register commands
app.command("version")(version.version_command)
app.command("register")(register.register)
pair_app.command("status")(pair_status.pair_status)
app.command("prove-lock")(prove_lock.prove_lock)
app.command("extend-lock")(extend_lock.extend_lock)
app.command("claim-deposit")(claim_deposit.claim_deposit)


if __name__ == "__main__":  # pragma: no cover
    app()
