"""Simplified helper for assembling and signing a demo LockProof payload with mock data."""

from __future__ import annotations

import json
import os
import random
from decimal import ROUND_DOWN, Decimal, InvalidOperation
from datetime import datetime, timezone
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

# Default output directory relative to testnet folder
OUTPUT_DIR = (Path(__file__).resolve().parent / "outputs").resolve()

# Mock values for demo
DEFAULT_CHAIN = 31337
DEFAULT_VAULT = "0x00000000000000000000000000000000000000aa"  # lowercase for consistency


def get_random_amount() -> str:
    """Generate a random float amount between 100 and 9999 USDC."""
    # Random float between 100.0 and 9999.0
    amount = random.uniform(100.0, 9999.0)
    # Round to 2 decimal places for USDC
    return f"{amount:.2f}"


def generate_random_tx_hash() -> str:
    """Generate a random 32-byte transaction hash."""
    return "0x" + "".join(random.choices("0123456789abcdef", k=64))


# pool_id helpers removed - not needed for signature generation


def generate_pool_id(pool_number: int) -> str:
    """Generate a pool ID hex string from a pool number (1-255).
    
    DEPRECATED: Use pool_name_to_id() with readable names instead.
    """
    if pool_number < 1 or pool_number > 255:
        raise ValueError("Pool number must be between 1 and 255")
    # Format as 0x0000...00XX where XX is the pool number in hex
    hex_pool = format(pool_number, "02x")
    return f"0x{'0' * 62}{hex_pool}"


def create_demo_evm_key() -> tuple[str, str]:
    """Create a demo EVM keypair and return (private_key, address)."""
    acct = Account.create()
    private_key = acct.key.hex()
    address = acct.address
    return private_key, address


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
        None,
        "--tx",
        help="Transaction hash. If not provided, a random hash will be generated.",
    ),
    # pool_id removed - not part of EIP-712 signature
    # In mainnet, verifier gets pool_id from on-chain events
    # In demo mode, verifier can use default Pool 1
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
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", help="Where to store the generated payload JSON. If not provided, auto-generates filename with timestamp."
    ),
) -> None:
    """Generate a LockProof payload with mock data for demo purposes.

    This script uses mock/default values suitable for demo:
    - Chain: 31337 (local/test)
    - Vault: Mock allowlisted vault address
    - TX: Random transaction hash (unless --tx provided)
    - Pool ID: Not included (verifier gets it from on-chain events in mainnet)
    - Amount: Prompted (defaults to a random float amount, 100-9999 USDC)
    - Lock Days: Read from on-chain event (set DEMO_LOCK_DAYS in verifier for demo mode)

    Set DEMO_SKIP_LOCKPROOF=1 in verifier to bypass on-chain validation.
    """

    console.print("[bold cyan]Cartha LockProof Builder (Demo Mode)[/]")
    console.print("Using mock data defaults for easy demo setup.\n")

    # Validate and normalize inputs
    if not Web3.is_address(vault):
        raise typer.BadParameter("Vault address must be a valid EVM address.")
    vault = Web3.to_checksum_address(vault)

    # Generate random TX hash if not provided
    if tx is None:
        tx_hash = generate_random_tx_hash()
        console.print(f"[dim]Generated random transaction hash:[/] [cyan]{tx_hash}[/]")
    else:
        tx_hash = _normalize_hex(tx.lower())
        if len(tx_hash) != 66:
            raise typer.BadParameter("Transaction hash must be 32 bytes (0x + 64 hex chars).")

    # pool_id removed - not part of EIP-712 signature
    # In mainnet, verifier gets pool_id from on-chain LockCreated events
    # This script only generates signatures, not pool assignments

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
    password = _normalize_hex(password.lower())  # Normalize to lowercase for consistency with verifier
    if len(password) != 66:
        raise typer.BadParameter("Password must be 32 bytes (0x + 64 hex chars).")

    # Get EVM private key (with auto-creation option)
    private_key = os.getenv("CARTHA_EVM_PK")
    miner_evm = None
    created_evm_key = False
    
    if not private_key:
        console.print("[yellow]Warning:[/] CARTHA_EVM_PK not set in environment.")
        if typer.confirm(
            "Would you like to create a mock EVM key automatically?", default=True
        ):
            console.print("[cyan]Creating mock EVM key...[/]")
            private_key, miner_evm_address = create_demo_evm_key()
            miner_evm = Web3.to_checksum_address(miner_evm_address)
            created_evm_key = True
            console.print(f"[green]✓ Created mock EVM key[/]")
            console.print(f"[dim]Address:[/] [cyan]{miner_evm}[/]")
            console.print(f"[dim]Private Key:[/] [yellow]{private_key}[/]")
            console.print(
                "\n[dim]Tip:[/] To reuse this key, export it:\n"
                f"[bold]export CARTHA_EVM_PK={private_key}[/]\n"
            )
        else:
            console.print(
                "[cyan]Alternative:[/] Generate a demo key with:\n"
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
    else:
        private_key = _normalize_hex(private_key)
        account = Account.from_key(private_key)
        miner_evm = Web3.to_checksum_address(account.address)

    # Get current timestamp
    import time

    timestamp = int(time.time())

    # Build EIP-712 message (lockDays removed - always read from on-chain event)
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
    )

    # Sign the message
    signable = message.encode()
    signed = Account.sign_message(signable, private_key=private_key)

    # Normalize signature: ensure single 0x prefix
    sig_hex = signed.signature.hex()
    if sig_hex.startswith("0x"):
        sig_hex = sig_hex[2:]
    signature_normalized = "0x" + sig_hex

    # Prepare payload (lockDays removed - always read from on-chain event)
    # Note: pool_id is used by verifier in demo mode (DEMO_SKIP_LOCKPROOF=1)
    # Create identifier name from hotkey and slot for easy tracking
    hotkey_short = hotkey[:8] + "..." + hotkey[-4:] if len(hotkey) > 12 else hotkey
    payload_name = f"{hotkey_short}_slot{slot}"
    
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
        # pool_id removed - not part of signature
        # In mainnet, verifier gets pool_id from on-chain events
        "_name": payload_name,
    }

    # Generate output filename with timestamp if not provided
    if output is None:
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_hotkey = hotkey_short.replace("...", "_").replace(".", "_")
        filename = f"lock_proof_{safe_hotkey}_slot{slot}_{timestamp_str}.json"
        output = OUTPUT_DIR / filename
    else:
        # Ensure output directory exists
        output.parent.mkdir(parents=True, exist_ok=True)

    # Save to file
    output.write_text(json.dumps(payload, indent=2))

    console.print(f"\n[bold green]✓ Saved[/] payload to [yellow]{output}[/]")
    
    # Show EVM address if it was created
    if created_evm_key:
        console.print(f"\n[bold cyan]EVM Address Created:[/] [green]{miner_evm}[/]")
        console.print(
            "[dim]This address was automatically generated for demo purposes.[/]\n"
        )
    
    console.print("\n[bold cyan]Command to submit lock proof:[/]\n")
    console.print(f"[green]uv run cartha vault lock --payload-file {output}[/]")
    console.print(f"[dim]Or use short alias:[/] [green]uv run cartha v lock --payload-file {output}[/]")
    console.print("\n[dim]Or manually with all parameters:[/]\n")
    console.print(
        f"[green]uv run cartha vault lock \\\n"
        f"  --chain {chain} \\\n"
        f"  --vault {vault} \\\n"
        f"  --tx {tx_hash} \\\n"
        f"  --amount {amount} \\\n"
        f"  --hotkey {hotkey} \\\n"
        f"  --slot {slot} \\\n"
        f"  --miner-evm {miner_evm} \\\n"
        f"  --pwd {password} \\\n"
        f"  --timestamp {timestamp} \\\n"
        f"  --signature {payload['signature']}[/]"
    )
    console.print(
        f"\n[dim]Note:[/] Amount {amount} USDC = {amount_base_units} base units (sent to verifier)"
    )
    console.print(
        "\n[dim]Note:[/] Pool ID is determined by verifier from on-chain events (mainnet) or defaults to Pool 1 (demo mode)"
    )
    console.print(
        "\n[dim]Note:[/] lockDays is read from on-chain event (set DEMO_LOCK_DAYS in verifier for demo mode)"
    )
    console.print(
        "\n[dim]Note:[/] Make sure DEMO_SKIP_LOCKPROOF=1 is set in verifier environment "
        "to bypass on-chain validation for demo."
    )


if __name__ == "__main__":
    app()
