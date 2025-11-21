"""Help and root command utilities."""

from rich import box
from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from ..display import get_clock_table
from .common import console


def print_root_help() -> None:
    """Print the root help message."""
    console.print(Rule("[bold cyan]Cartha CLI[/]"))
    console.print(
        "Miner-facing command line tool for Cartha subnet miners.\n"
        "Authenticate against the verifier, inspect pair status, and submit LockProof payloads."
    )
    console.print()
    console.print("[bold]Usage[/]: cartha [OPTIONS] COMMAND [ARGS]...")
    console.print()

    options = Table(title="Options", box=box.SQUARE_DOUBLE_HEAD, show_header=False)
    options.add_row("[cyan]-h[/], [cyan]--help[/]", "Show this message and exit.")
    console.print(options)
    console.print()

    commands = Table(title="Commands", box=box.SQUARE_DOUBLE_HEAD, show_header=False)
    commands.add_row("[green]version[/]", "Show CLI version.")
    commands.add_row(
        "[green]register[/]", "Register a hotkey and fetch the pair password."
    )
    commands.add_row(
        "[green]pair status[/]", "Sign a challenge and display pair metadata."
    )
    commands.add_row(
        "[green]prove-lock[/]", "Submit an externally signed LockProof payload."
    )
    commands.add_row(
        "[green]extend-lock[/]", "Extend lock period by submitting new lock proof with updated lock days."
    )
    commands.add_row(
        "[green]claim-deposit[/]", "Alias for prove-lock (deposit-first flow)."
    )
    console.print(commands)
    console.print()

    # Display clock and countdown in a separate table
    clock_table = get_clock_table()
    console.print(clock_table)
    console.print()

    console.print("[dim]Made with ❤ by GTV[/]")

