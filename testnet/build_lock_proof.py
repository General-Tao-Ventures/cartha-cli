"""Simplified helper for assembling and signing a demo LockProof payload with mock data."""

from __future__ import annotations

import json
import os
import random
from decimal import ROUND_DOWN, Decimal, InvalidOperation
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Prompt
from web3 import Web3

try:
    from cartha_cli.eth712 import LockProofMessage
except ImportError as exc:
    raise SystemExit(
        "cartha-cli not found. Make sure you're running this from the cartha-cli repo "
        "and dependencies are installed: uv sync"
    ) from exc

try:
    from eth_account import Account
except ImportError as exc:
    raise SystemExit("eth-account is required. Run: uv sync") from exc

app = typer.Typer(add_completion=False)
console = Console()

# Default output path relative to testnet folder
OUTPUT_PATH = (Path(__file__).resolve().parent / "outputs" / "lock_proof_payload.json").resolve()

# Mock values for demo
DEFAULT_CHAIN = 31337
DEFAULT_VAULT = "0x00000000000000000000000000000000000000aa"  # lowercase for consistency
DEFAULT_TX = "0x1111111111111111111111111111111111111111111111111111111111111111"


def get_random_amount() -> str:
    """Generate a random float amount between 100 and 9999 USDC."""
    # Random float between 100.0 and 9999.0
    amount = random.uniform(100.0, 9999.0)
    # Round to 2 decimal places for USDC
    return f"{amount:.2f}"


def get_random_lock_days() -> int:
    """Generate a random lock period between 7 and 365 days."""
    return random.randint(7, 365)


def _normalize_hex(value: str, prefix: str = "0x") -> str:
    value = value.strip()
    if not value.startswith(prefix):
        value = prefix + value
    return value


def to_base_units(value: str) -> int:
    """Convert USDC amount to base units (6 decimals)."""
    try:
        decimal_value = Decimal(value)
    except InvalidOperation as exc:
        raise typer.BadParameter("Amount must be a numeric value.") from exc
    if decimal_value <= 0:
        raise typer.BadParameter("Amount must be positive.")
    quantized = decimal_value.quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
    return int(quantized * 10**6)


@app.command()
def main(
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
        DEFAULT_TX,
        "--tx",
        help="Transaction hash (default: mock hash for demo).",
    ),
    amount: str = typer.Option(
        None,
        "--amount",
        help="Deposit amount in USDC. If not provided, you'll be prompted.",
    ),
    hotkey: str = typer.Option(
        None, "--hotkey", help="Miner hotkey (SS58). Required if not in env."
    ),
    slot: str = typer.Option(None, "--slot", help="Miner slot UID. Required if not in env."),
    pwd: str = typer.Option(None, "--pwd", help="Pair password (0x...). Required if not in env."),
    lock_days: int = typer.Option(  # noqa: B008
        None,
        "--lock-days",
        help="Lock period in days (min 7, max 365). If not provided, you'll be prompted.",
    ),
    output: Path = typer.Option(  # noqa: B008
        OUTPUT_PATH, "--output", help="Where to store the generated payload JSON."
    ),
) -> None:
    """Generate a LockProof payload with mock data for demo purposes.

    This script uses mock/default values suitable for demo:
    - Chain: 31337 (local/test)
    - Vault: Mock allowlisted vault address
    - TX: Mock transaction hash
    - Amount: Prompted (defaults to a random float amount, 100-9999 USDC)

    Set DEMO_SKIP_LOCKPROOF=1 in verifier to bypass on-chain validation.
    """

    console.print("[bold cyan]Cartha LockProof Builder (Demo Mode)[/]")
    console.print("Using mock data defaults for easy demo setup.\n")

    # Validate and normalize inputs
    if not Web3.is_address(vault):
        raise typer.BadParameter("Vault address must be a valid EVM address.")
    vault = Web3.to_checksum_address(vault)

    tx_hash = _normalize_hex(tx.lower())
    if len(tx_hash) != 66:
        raise typer.BadParameter("Transaction hash must be 32 bytes (0x + 64 hex chars).")

    # Prompt for amount if not provided
    if amount is None:
        random_default = get_random_amount()
        amount = Prompt.ask(
            "Deposit amount in USDC",
            default=random_default,
        )

    amount_base_units = to_base_units(amount)

    # Get required inputs from args or env
    hotkey_val: str = hotkey or os.getenv("CARTHA_DEMO_HOTKEY") or ""
    if not hotkey_val:
        hotkey_val = Prompt.ask("Miner hotkey (SS58)")
    hotkey = hotkey_val

    slot_val: str | None = slot or os.getenv("CARTHA_DEMO_SLOT")
    if not slot_val:
        slot_val = Prompt.ask("Miner slot UID")
    slot = str(slot_val)

    password = pwd or os.getenv("CARTHA_DEMO_PASSWORD")
    if not password:
        password = Prompt.ask("Pair password (0x...)", default="0x")
    password = _normalize_hex(password)
    if len(password) != 66:
        raise typer.BadParameter("Password must be 32 bytes (0x + 64 hex chars).")

    # Get EVM private key
    private_key = os.getenv("CARTHA_EVM_PK")
    if not private_key:
        console.print("[yellow]Warning:[/] CARTHA_EVM_PK not set.")
        console.print(
            "[cyan]Quick fix:[/] Generate a demo key with:\n"
            "  [green]uv run python testnet/create_demo_evm_key.py --output testnet/outputs/evm_key.json[/]\n"
            "  [green]export CARTHA_EVM_PK=$(jq -r .CARTHA_EVM_PK testnet/outputs/evm_key.json)[/]\n"
        )
        if not typer.confirm(
            "Continue anyway? (You'll need to paste a private key)", default=False
        ):
            raise typer.Abort()
        private_key = typer.prompt("Paste demo private key (0x...)", hide_input=True)
    private_key = _normalize_hex(private_key)

    account = Account.from_key(private_key)
    miner_evm = Web3.to_checksum_address(account.address)

    # Prompt for lock_days if not provided (with random default)
    if lock_days is None:
        random_default = get_random_lock_days()
        lock_days_input = Prompt.ask(
            "Lock period in days (min 7, max 365)",
            default=str(random_default),
        )
        try:
            lock_days = int(lock_days_input)
            if lock_days < 7 or lock_days > 365:
                raise typer.BadParameter("Lock period must be between 7 and 365 days.")
        except ValueError:
            raise typer.BadParameter("Lock period must be a valid integer.")
    else:
        # Validate provided lock_days
        if lock_days < 7 or lock_days > 365:
            raise typer.BadParameter("Lock period must be between 7 and 365 days.")

    # Get current timestamp
    import time

    timestamp = int(time.time())

    # Build EIP-712 message
    message = LockProofMessage(
        chain_id=chain,
        vault_address=vault,
        miner_evm_address=miner_evm,
        miner_hotkey=hotkey,
        slot_uid=slot,
        tx_hash=tx_hash,
        amount=amount_base_units,
        password=password,
        timestamp=timestamp,
        lock_days=lock_days,
    )

    # Sign the message
    signable = message.encode()
    signed = Account.sign_message(signable, private_key=private_key)

    # Normalize signature: ensure single 0x prefix
    sig_hex = signed.signature.hex()
    if sig_hex.startswith("0x"):
        sig_hex = sig_hex[2:]
    signature_normalized = "0x" + sig_hex

    # Prepare payload
    payload = {
        "chain": chain,
        "vault": vault,
        "tx": tx_hash,
        "amount": amount_base_units,
        "amountNormalized": amount,
        "hotkey": hotkey,
        "slot": slot,
        "miner_evm": miner_evm,
        "password": password,
        "timestamp": timestamp,
        "signature": signature_normalized,
        "lock_days": lock_days,
    }

    # Save to file
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2))

    console.print(f"\n[bold green]✓ Saved[/] payload to [yellow]{output}[/]")
    console.print("\n[bold cyan]Command to submit lock proof:[/]\n")
    console.print(f"[green]uv run cartha prove-lock --payload-file {output}[/]")
    console.print("\n[dim]Or manually with all parameters:[/]\n")
    console.print(
        f"[green]uv run cartha prove-lock \\\n"
        f"  --chain {chain} \\\n"
        f"  --vault {vault} \\\n"
        f"  --tx {tx_hash} \\\n"
        f"  --amount {amount} \\\n"
        f"  --hotkey {hotkey} \\\n"
        f"  --slot {slot} \\\n"
        f"  --miner-evm {miner_evm} \\\n"
        f"  --pwd {password} \\\n"
        f"  --timestamp {timestamp} \\\n"
        f"  --lock-days {lock_days} \\\n"
        f"  --signature {payload['signature']}[/]"
    )
    console.print(
        f"\n[dim]Note:[/] Amount {amount} USDC = {amount_base_units} base units (sent to verifier)"
    )
    console.print(
        "\n[dim]Note:[/] Make sure DEMO_SKIP_LOCKPROOF=1 is set in verifier environment "
        "to bypass on-chain validation for demo."
    )


if __name__ == "__main__":
    app()
