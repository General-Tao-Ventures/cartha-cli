"""Generate a throwaway EVM key for demo purposes."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

try:
    from eth_account import Account
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "eth-account is required. Run: uv sync"
    ) from exc


app = typer.Typer(add_completion=False)
console = Console()


@app.command()
def main(
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "--output",
        help="Optional path to write a JSON blob containing CARTHA_EVM_PK and address.",
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Allow overwriting an existing output file.",
    ),
) -> None:
    """Generate a new demo private key and print export instructions."""

    acct = Account.create()
    private_key = acct.key.hex()
    address = acct.address

    console.print("[bold green]Generated demo EVM key[/]")
    console.print(f"Address : [cyan]{address}[/]")
    console.print(f"PrivKey : [yellow]{private_key}[/]")
    console.print(
        "\nExport this in your shell before running the lock-proof builder:\n"
        f"[bold]export CARTHA_EVM_PK={private_key}[/]"
    )

    if output is not None:
        output = output.expanduser().resolve()
        if output.exists() and not overwrite:
            raise typer.BadParameter(
                f"{output} already exists. Use --overwrite to replace it."
            )
        output.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "CARTHA_EVM_PK": private_key,
            "CARTHA_DEMO_EVM_ADDRESS": address,
        }
        output.write_text(json.dumps(payload, indent=2))
        console.print(f"\n[bold green]Saved JSON[/] to [cyan]{output}[/]")
        console.print(
            f"\nTo load the key, run:\n"
            f"[bold]export CARTHA_EVM_PK=$(jq -r .CARTHA_EVM_PK {output})[/]"
        )


if __name__ == "__main__":
    app()

