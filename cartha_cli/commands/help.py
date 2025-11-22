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
    commands.add_row("[green]help[/]", "Show this help message.")
    commands.add_row("[green]version[/]", "Show CLI version.")
    commands.add_row(
        "[green]miner[/] [dim](or [green]m[/])[/]", "Miner management commands."
    )
    commands.add_row(
        "[green]portfolio[/] [dim](or [green]p[/])[/]", "Portfolio management commands."
    )
    console.print(commands)
    console.print()

    # Show miner subcommands
    miner_commands = Table(
        title="Miner Commands", box=box.SQUARE_DOUBLE_HEAD, show_header=False
    )
    miner_commands.add_row(
        "[green]miner status[/]",
        "Show miner status and pool information (no password).",
    )
    miner_commands.add_row(
        "[green]miner password[/]", "Show miner password (requires authentication)."
    )
    miner_commands.add_row(
        "[green]miner register[/]", "Register a hotkey on the subnet."
    )
    console.print(miner_commands)
    console.print()

    # Show portfolio subcommands
    portfolio_commands = Table(
        title="Portfolio Commands", box=box.SQUARE_DOUBLE_HEAD, show_header=False
    )
    portfolio_commands.add_row(
        "[green]portfolio lock[/]", "Submit a LockProof payload to lock funds."
    )
    portfolio_commands.add_row(
        "[green]portfolio claim[/]", "Alias for lock (deposit-first flow)."
    )
    console.print(portfolio_commands)
    console.print()

    # Display clock and countdown in a separate table
    clock_table = get_clock_table()
    console.print(clock_table)
    console.print()

    console.print("[dim]Made with ❤ by GTV[/]")
