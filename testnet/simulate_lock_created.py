"""Simulate LockCreated events for testing initial lock creation.

This script simulates vault events that represent a miner creating a new lock
position in a specific pool. Useful for testing:
- New pool lock creation
- Initial lock with specific amount and lock days
- Multiple pools per miner (separate LockCreated events)
"""

from __future__ import annotations

import json
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
DEFAULT_LOCK_DAYS = 30


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
    amount: int = typer.Option(  # noqa: B008
        None,
        "--amount",
        help="Lock amount in USDC. If not provided, you'll be prompted.",
    ),
    lock_days: int = typer.Option(  # noqa: B008
        None,
        "--lock-days",
        help=f"Lock period in days (min 7, max 365). Default: {DEFAULT_LOCK_DAYS}",
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
    """Simulate a LockCreated event for testing initial lock creation.

    This script generates event details that represent a miner creating a new lock
    position in a specific pool. The verifier will detect this event when validating
    a prove-lock submission.

    Note: Miners must still run `cartha prove-lock` with the transaction hash to
    link their Bittensor hotkey to this EVM lock. This script is for testing the
    event structure and verifier detection.

    Example usage:
        # Simulate a new lock in USDEUR pool
        python simulate_lock_created.py --evm 0x... --amount 1000 --lock-days 30

        # Simulate a new lock in XAUUSD pool
        python simulate_lock_created.py --evm 0x... --pool-id XAUUSD --amount 500 --lock-days 60

        # Use specific transaction hash
        python simulate_lock_created.py --evm 0x... --tx 0x1234... --amount 1000
    """

    console.print("[bold cyan]Cartha LockCreated Event Simulator[/]")
    console.print("Simulates initial lock creation events for testing.\n")

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

    # Handle amount
    if amount is None:
        amount_input = Prompt.ask("Lock amount (USDC)", default="1000")
        try:
            amount = int(float(amount_input) * 1_000_000)  # Convert to base units
        except ValueError:
            raise typer.BadParameter("Amount must be a numeric value.")
    else:
        # Assume provided value is in USDC, convert to base units
        amount = int(amount * 1_000_000)

    # Handle lock_days
    if lock_days is None:
        lock_days = DEFAULT_LOCK_DAYS
    else:
        if lock_days < 7 or lock_days > 365:
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
        "event": "LockCreated",
        "chain_id": chain,
        "vault": vault,
        "owner": evm_address,
        "poolId": pool_id,
        "amount": amount,
        "lockDays": lock_days,
        "txHash": tx_hash,
    }

    # Display summary
    console.print("\n[bold green]Event Details:[/]\n")
    console.print(f"  Event Type:     [cyan]LockCreated[/]")
    console.print(f"  Chain ID:       [cyan]{chain}[/]")
    console.print(f"  Vault:          [cyan]{vault}[/]")
    console.print(f"  Owner (EVM):    [cyan]{evm_address}[/]")
    pool_display = format_pool_id(pool_id)
    console.print(f"  Pool ID:        [cyan]{pool_display}[/]")
    console.print(
        f"  Amount:         [cyan]{amount}[/] base units "
        f"([cyan]{amount / 1_000_000:.2f}[/] USDC)"
    )
    console.print(f"  Lock Days:      [cyan]{lock_days}[/]")
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
        "[dim]1. This event represents a new lock position created on-chain[/]"
    )
    console.print(
        "[dim]2. The miner must run:[/] [green]cartha prove-lock --tx {tx_hash} --pool-id {pool_id}[/]"
    )
    console.print(
        "[dim]3. The verifier will validate this LockCreated event during prove-lock[/]"
    )
    console.print(
        "[dim]4. After prove-lock succeeds, future LockUpdated events will auto-update[/]"
    )
    console.print(
        "\n[dim]Note:[/] This script simulates the event structure. The actual event must exist "
        "on-chain for prove-lock to succeed (or use DEMO_SKIP_LOCKPROOF=1 in verifier)."
    )


if __name__ == "__main__":
    app()

