"""Helper functions for prove-lock command."""

from __future__ import annotations

import time
from typing import Any

import typer
from web3 import Web3

try:
    from eth_account import Account
except ImportError:
    Account = None  # type: ignore

from ..eth712 import LockProofMessage
from ..utils import normalize_hex
from ..verifier import VerifierError, submit_lock_proof
from .common import console, exit_with_error


def submit_lock_proof_payload(
    *,
    chain: int,
    vault: str,
    tx_hash: str,
    amount: int,
    hotkey: str,
    slot: str,
    miner_evm: str,
    password: str,
    signature: str,
    timestamp: int | None = None,
) -> dict[str, Any]:
    """Create and validate a lock proof payload."""
    if amount <= 0:
        console.print("[bold red]Amount must be a positive integer.[/]")
        raise typer.Exit(code=1)

    if not Web3.is_address(vault):
        console.print("[bold red]Vault address must be a valid EVM address.[/]")
        raise typer.Exit(code=1)
    if not Web3.is_address(miner_evm):
        console.print("[bold red]Miner EVM address must be a valid address.[/]")
        raise typer.Exit(code=1)

    if not tx_hash.startswith("0x"):
        console.print("[bold red]Transaction hash must be a 0x-prefixed hex string.[/]")
        raise typer.Exit(code=1)

    if not signature.startswith("0x"):
        signature = "0x" + signature

    # Use provided timestamp if available (from build_lock_proof.py), otherwise generate new one
    if timestamp is None:
        timestamp = int(time.time())

    return {
        "vaultAddress": Web3.to_checksum_address(vault),
        "minerEvmAddress": Web3.to_checksum_address(miner_evm),
        "minerHotkey": hotkey,
        "slotUID": slot,
        "chainId": chain,
        "txHash": tx_hash.lower(),
        "amount": amount,
        "pwd": password,
        "timestamp": timestamp,
        "signature": signature,
    }


def generate_eip712_signature(
    *,
    chain_id: int,
    vault_address: str,
    miner_hotkey: str,
    slot_uid: str,
    tx_hash: str,
    amount: int,
    password: str,
    timestamp: int,
    private_key: str,
) -> tuple[str, str]:
    """Generate EIP-712 signature for LockProof.

    Args:
        chain_id: EVM chain ID
        vault_address: Vault contract address
        miner_hotkey: Bittensor hotkey (SS58)
        slot_uid: Slot UID
        tx_hash: Transaction hash
        amount: Amount in base units
        password: Pair password (0x-prefixed hex)
        timestamp: Unix timestamp
        private_key: EVM private key (0x-prefixed hex)

    Returns:
        Tuple of (signature, miner_evm_address)
    """
    if Account is None:
        exit_with_error(
            "eth-account is required for EIP-712 signing. Install it with: uv sync"
        )

    # Normalize private key
    private_key_normalized = normalize_hex(private_key)

    # Derive EVM address from private key
    account = Account.from_key(private_key_normalized)
    miner_evm_address = Web3.to_checksum_address(account.address)

    # Normalize password
    password_normalized = normalize_hex(password)
    if len(password_normalized) != 66:  # 0x + 64 hex chars = 32 bytes
        exit_with_error("Password must be 32 bytes (0x + 64 hex characters)")

    # Normalize tx hash
    tx_hash_normalized = normalize_hex(tx_hash.lower())
    if len(tx_hash_normalized) != 66:  # 0x + 64 hex chars = 32 bytes
        exit_with_error("Transaction hash must be 32 bytes (0x + 64 hex characters)")

    # Build EIP-712 message (without lockDays - read from on-chain event)
    message = LockProofMessage(
        chain_id=chain_id,
        vault_address=vault_address,
        miner_evm_address=miner_evm_address,
        miner_hotkey=miner_hotkey,
        slot_uid=slot_uid,
        tx_hash=tx_hash_normalized,
        amount=amount,
        password=password_normalized,
        timestamp=timestamp,
    )

    # Sign the message
    signable = message.encode()
    signed = Account.sign_message(signable, private_key=private_key_normalized)

    # Normalize signature: ensure single 0x prefix
    sig_hex = signed.signature.hex()
    if sig_hex.startswith("0x"):
        sig_hex = sig_hex[2:]
    signature_normalized = "0x" + sig_hex

    return signature_normalized, miner_evm_address


def send_lock_proof(payload: dict[str, Any], json_output: bool) -> None:
    """Send lock proof to verifier."""
    from rich.json import JSON

    try:
        response = submit_lock_proof(payload)
    except VerifierError as exc:
        error_msg = str(exc)

        # Check for EVM address conflict (409 CONFLICT)
        if exc.status_code == 409 and (
            "already claimed" in error_msg.lower()
            or "claimed by another identity" in error_msg.lower()
        ):
            console.print(
                "[bold red]Lock proof rejected[/]: Multiple hotkeys cannot claim the same EVM address"
            )
            evm_addr = payload.get("minerEvmAddress", "unknown")
            console.print(
                "[yellow]Error details[/]: "
                f"This EVM wallet ({evm_addr}) has already been linked "
                f"to another hotkey in this epoch. Each EVM wallet position can only be claimed by "
                f"one hotkey per epoch."
            )
            console.print(
                "[dim]Tip[/]: If you want to link this deposit to a different hotkey, you must wait "
                "until the next epoch or use a different EVM wallet."
            )
        else:
            console.print(f"[bold red]Lock proof rejected[/]: {error_msg}")
        raise typer.Exit(code=1) from exc

    if json_output:
        console.print(JSON.from_data(response))
    else:
        console.print("[bold green]Lock proof submitted successfully.[/]")

