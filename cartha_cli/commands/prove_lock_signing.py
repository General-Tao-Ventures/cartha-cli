"""External signing helpers for prove-lock command."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import typer
from web3 import Web3

from ..eth712 import LockProofMessage
from ..utils import normalize_hex
from .common import console


def generate_external_signing_files(
    chain: int,
    vault: str,
    miner_evm: str,
    hotkey: str,
    slot: int,
    tx: str,
    amount_base_units: int,
    password: str,
    timestamp: int,
) -> tuple[Path, Path]:
    """Generate EIP-712 signing files for external signing.

    Returns tuple of (json_filename, txt_filename)
    """
    # Build EIP-712 message structure (without lockDays - read from on-chain event)
    eip712_message = LockProofMessage(
        chain_id=chain,
        vault_address=Web3.to_checksum_address(vault),
        miner_evm_address=miner_evm,
        miner_hotkey=hotkey,
        slot_uid=str(slot),
        tx_hash=tx.lower(),
        amount=amount_base_units,
        password=password.lower(),
        timestamp=timestamp,
    )
    typed_data = eip712_message.to_eip712()

    # Convert HexBytes to strings for JSON serialization
    def hexbytes_to_str(obj: Any) -> str:
        """Convert HexBytes to hex string for JSON serialization."""
        from hexbytes import HexBytes

        if isinstance(obj, HexBytes):
            return obj.hex()
        raise TypeError(
            f"Object of type {type(obj)} is not JSON serializable"
        )

    # Serialize to JSON with HexBytes conversion
    json_str = json.dumps(typed_data, default=hexbytes_to_str, indent=2)

    # Create output directory if it doesn't exist
    output_dir = Path.cwd() / "cartha_eip712_outputs"
    output_dir.mkdir(exist_ok=True)

    # Generate filename with timestamp
    timestamp_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    json_filename = output_dir / f"eip712_message_{timestamp_str}.json"
    txt_filename = output_dir / f"eip712_instructions_{timestamp_str}.txt"

    # Save JSON file (ready to use with MetaMask, ethers.js, etc.)
    with open(json_filename, "w") as f:
        f.write(json_str)

    # Create human-readable instructions file
    human_amount = Decimal(amount_base_units) / Decimal(10**6)
    amount_str = f"{human_amount:.6f}".rstrip("0").rstrip(".")

    instructions = f"""EIP-712 LockProof Signing Instructions
Generated: {datetime.now(UTC).isoformat()}

IMPORTANT: Copy the JSON from {json_filename.name} exactly as-is. Do not modify any values, spacing, or formatting.

NOTE: lockDays is no longer included in the signature - it's read from the on-chain LockCreated event.

=== Message Details ===
Chain ID: {chain}
Vault Address: {vault}
Miner EVM Address: {miner_evm}
Hotkey: {hotkey}
Slot UID: {slot}
Transaction Hash: {tx}
Amount: {amount_str} USDC ({amount_base_units} base units)
Pair Password: {password}
Timestamp: {timestamp}

=== How to Sign ===

Option 1: MetaMask (Browser)
1. Open MetaMask and connect to Chain ID {chain}
2. Open browser console (F12)
3. Copy the entire contents of {json_filename.name} and run:
   const message = <paste entire JSON here>;
   const account = "0x..."; // Your MetaMask account (use window.ethereum.selectedAddress)
   const signature = await window.ethereum.request({{
     method: "eth_signTypedData_v4",
     params: [account, JSON.stringify(message)]
   }});
   console.log("Signature:", signature);
   
   Note: Make sure to copy the JSON exactly as-is, including all brackets and quotes.

Option 2: ethers.js
const {{ ethers }} = require("ethers");
const provider = new ethers.providers.Web3Provider(window.ethereum);
const signer = provider.getSigner();
const message = <paste JSON from {json_filename.name}>;
const signature = await signer._signTypedData(
  message.domain,
  message.types,
  message.message
);
console.log("Signature:", signature);

Option 3: Other Tools
Use the JSON from {json_filename.name} with any EIP-712 compatible signing tool.

=== After Signing ===
1. Copy the signature (should start with 0x and be 132 characters total)
2. Return to the CLI and paste the signature when prompted

=== Security Notes ===
- Never share your private key or pair password
- Verify all values match your deposit transaction
- The signature proves you control the EVM address that made the deposit
"""

    with open(txt_filename, "w") as f:
        f.write(instructions)

    return json_filename, txt_filename


def collect_external_signature() -> str:
    """Collect signature from user after external signing."""
    console.print("\n[bold yellow]Next steps:[/]")
    console.print("1. Open the JSON file and copy its contents")
    console.print(
        "2. Use MetaMask, ethers.js, or another EIP-712 compatible tool to sign"
    )
    console.print("3. Copy the signature (0x + 130 hex characters)")
    console.print("4. Return here and paste the signature when prompted")
    console.print(
        "\n[dim]Tip:[/] The JSON file is formatted exactly as needed - copy it as-is without modifications."
    )
    console.print(
        "\n[bold cyan]Press Enter when you have your signature ready...[/]"
    )
    input()  # Wait for user to press Enter

    while True:
        signature = typer.prompt(
            "Paste your EIP-712 signature (0x...)", show_default=False
        )
        signature_normalized = normalize_hex(signature)
        # EIP-712 signature is 65 bytes = 0x + 130 hex chars
        if len(signature_normalized) == 132:
            return signature_normalized
        console.print(
            "[bold red]Error:[/] Signature must be 65 bytes (0x + 130 hex characters)"
        )

