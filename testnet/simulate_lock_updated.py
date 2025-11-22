"""Simulate LockUpdated events (top-ups, withdrawals, and lock extensions) for testing.

This script simulates vault events that the verifier's hint watcher will detect
and automatically update the database. Useful for testing:
- Top-ups: Increase locked amount (deltaAmount > 0)
- Withdrawals: Decrease locked amount (deltaAmount < 0)
- Lock extensions: Extend lock period (newLockDays > current, deltaAmount = 0)
- Combinations: Top-up + extension, withdrawal + extension, etc.

Note: The miner must have already proven-lock for this pool before LockUpdated
events will auto-update the database. LockUpdated only updates existing entries
in the upcoming epoch (never frozen epochs).
"""

from __future__ import annotations

import json
import os
import random
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Prompt
from web3 import Web3

try:
    from eth_account import Account
except ImportError as exc:
    raise SystemExit("eth-account is required. Run: uv sync") from exc

try:
    from .pool_ids import pool_name_to_id, format_pool_id, list_pools
except ImportError:
    # Fallback if running as script
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent))
    from pool_ids import pool_name_to_id, format_pool_id, list_pools

app = typer.Typer(add_completion=False)
console = Console()

# Default values
DEFAULT_CHAIN = 31337
DEFAULT_VAULT = "0x00000000000000000000000000000000000000aa"


def generate_random_tx_hash() -> str:
    """Generate a random 32-byte transaction hash."""
    return "0x" + "".join(random.choices("0123456789abcdef", k=64))




def _normalize_hex(value: str, prefix: str = "0x") -> str:
    value = value.strip()
    if not value.startswith(prefix):
        value = prefix + value
    return value.lower()


@app.command()
def main(
    evm_address: str = typer.Option(
        None,
        "--evm",
        help="EVM address of the miner (owner). Required.",
    ),
    pool_id: str = typer.Option(
        None,
        "--pool-id",
        help="Pool ID (readable name like 'USDEUR', 'XAUUSD', or hex string). Defaults to 'USDEUR'.",
    ),
    delta_amount: int = typer.Option(  # noqa: B008
        None,
        "--delta-amount",
        help="Change in amount (+top-up, -withdrawal). If not provided, you'll be prompted.",
    ),
    new_lock_days: int = typer.Option(  # noqa: B008
        None,
        "--new-lock-days",
        help="New lock days (for extension). If not provided, only amount is updated.",
    ),
    chain: int = typer.Option(
        DEFAULT_CHAIN,
        "--chain",
        help=f"EVM chain ID (default: {DEFAULT_CHAIN} for demo).",
    ),
    vault: str = typer.Option(
        DEFAULT_VAULT,
        "--vault",
        help=f"Vault contract address (default: {DEFAULT_VAULT} for demo).",
    ),
    tx: str = typer.Option(
        None,
        "--tx",
        help="Transaction hash. If not provided, a random hash will be generated.",
    ),
    output: Path = typer.Option(  # noqa: B008
        None,
        "--output",
        help="Optional: Save event details to JSON file.",
    ),
) -> None:
    """Simulate a LockUpdated event for testing top-ups, withdrawals, and lock extensions.

    This script generates event details that can be used to test the verifier's
    automatic database updates when vault events are detected.

    The verifier's hint watcher polls vaults and will detect these events
    (if they exist on-chain or in demo mode). The verifier will automatically:
    - Update the miner's amount (amount += deltaAmount)
    - Update lock_days if newLockDays > current lock_days
    - Only update entries in the upcoming epoch (never frozen epochs)

    Example usage:
        # Simulate a top-up of 1000 USDC
        python simulate_lock_updated.py --evm 0x... --delta-amount 1000

        # Simulate a withdrawal of 500 USDC
        python simulate_lock_updated.py --evm 0x... --delta-amount -500

        # Simulate lock extension to 90 days (no amount change)
        python simulate_lock_updated.py --evm 0x... --new-lock-days 90

        # Simulate both top-up and extension
        python simulate_lock_updated.py --evm 0x... --delta-amount 500 --new-lock-days 60

        # Use different pool
        python simulate_lock_updated.py --evm 0x... --pool-id XAUUSD --delta-amount 1000
    """

    console.print("[bold cyan]Cartha LockUpdated Event Simulator[/]")
    console.print("Simulates vault events for testing automatic database updates.\n")

    # Validate inputs
    if not evm_address:
        evm_address = Prompt.ask("EVM address (owner)")
    evm_address = Web3.to_checksum_address(evm_address)

    if not Web3.is_address(vault):
        raise typer.BadParameter("Vault address must be a valid EVM address.")
    vault = Web3.to_checksum_address(vault)

    # Handle pool_id (accept readable names or hex)
    if pool_id is None:
        pool_id = pool_name_to_id("USDEUR")
        console.print(f"[dim]Using default pool:[/] [cyan]USDEUR[/] ({pool_id})")
    else:
        # Check if it's a readable name first
        pool_id_upper = pool_id.upper()
        if pool_id_upper in list_pools():
            readable_name = pool_id_upper
            pool_id = pool_name_to_id(readable_name)
            console.print(f"[dim]Using pool:[/] [cyan]{readable_name}[/] ({pool_id})")
        else:
            # Assume it's a hex string
            pool_id = _normalize_hex(pool_id)
            if len(pool_id) != 66:
                raise typer.BadParameter(
                    "Pool ID must be a readable name (USDEUR, XAUUSD, etc.) "
                    "or a hex string (0x + 64 hex chars)."
                )
            readable_name = format_pool_id(pool_id)
            console.print(f"[dim]Using pool ID:[/] [cyan]{readable_name}[/]")

    # Handle delta_amount (can be 0 for lock-days-only updates)
    if delta_amount is None:
        if new_lock_days is not None:
            # If only updating lock days, default to 0 (no amount change)
            delta_input = Prompt.ask(
                "Delta amount (USDC, +top-up, -withdrawal, 0 for lock-days-only)",
                default="0",
            )
        else:
            # If updating amount, prompt with default
            delta_input = Prompt.ask(
                "Delta amount (USDC, +top-up, -withdrawal)",
                default="1000",
            )
        try:
            delta_amount = int(float(delta_input) * 1_000_000)  # Convert to base units
        except ValueError:
            raise typer.BadParameter("Delta amount must be a numeric value.")
    else:
        # Assume provided value is in USDC, convert to base units
        delta_amount = int(delta_amount * 1_000_000)

    # Handle new_lock_days
    if new_lock_days is not None:
        if new_lock_days < 7 or new_lock_days > 365:
            raise typer.BadParameter("Lock days must be between 7 and 365.")

    # Generate random TX hash if not provided
    if tx is None:
        tx_hash = generate_random_tx_hash()
        console.print(f"[dim]Generated random transaction hash:[/] [cyan]{tx_hash}[/]")
    else:
        tx_hash = _normalize_hex(tx)
        if len(tx_hash) != 66:
            raise typer.BadParameter("Transaction hash must be 32 bytes (0x + 64 hex chars).")

    # Build event details
    event_details = {
        "event": "LockUpdated",
        "chain_id": chain,
        "vault": vault,
        "owner": evm_address,
        "poolId": pool_id,
        "deltaAmount": delta_amount,
        "newLockDays": new_lock_days,
        "txHash": tx_hash,
    }

    # Display summary
    console.print("\n[bold green]Event Details:[/]\n")
    console.print(f"  Event Type:     [cyan]LockUpdated[/]")
    console.print(f"  Chain ID:       [cyan]{chain}[/]")
    console.print(f"  Vault:          [cyan]{vault}[/]")
    console.print(f"  Owner (EVM):    [cyan]{evm_address}[/]")
    pool_display = format_pool_id(pool_id)
    console.print(f"  Pool ID:        [cyan]{pool_display}[/]")
    
    if delta_amount == 0 and new_lock_days is not None:
        console.print(f"  Delta Amount:   [dim]0 (lock-days-only update)[/]")
    else:
        console.print(
            f"  Delta Amount:   [cyan]{delta_amount:+d}[/] base units "
            f"([cyan]{delta_amount / 1_000_000:+.2f}[/] USDC)"
        )
    
    if new_lock_days is not None:
        console.print(f"  New Lock Days:  [cyan]{new_lock_days}[/]")
    else:
        console.print(f"  New Lock Days:  [dim]None (amount only)[/]")
    console.print(f"  TX Hash:        [cyan]{tx_hash}[/]")

    # Save to file if requested
    if output:
        output = output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(event_details, indent=2))
        console.print(f"\n[bold green]✓ Saved[/] event details to [yellow]{output}[/]")

    # Instructions
    console.print("\n[bold cyan]How to Use:[/]\n")
    console.print(
        "[dim]1. This event will be detected by the verifier's hint watcher[/]"
    )
    console.print(
        "[dim]2. The verifier will automatically update the database for the upcoming epoch[/]"
    )
    console.print(
        "[dim]3. Check verifier logs for:[/] [cyan][VAULT EVENT] LockUpdated detected[/]"
    )
    console.print(
        "[dim]4. Verify the update with:[/] [green]cartha pair status[/]"
    )
    console.print(
        "\n[dim]Note:[/] In demo mode, you may need to manually trigger the hint watcher "
        "or wait for the next poll interval."
    )


if __name__ == "__main__":
    app()

