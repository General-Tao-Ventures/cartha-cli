"""Payload file loading and validation for prove-lock command."""

from __future__ import annotations

import json
from decimal import InvalidOperation
from pathlib import Path

import typer
from web3 import Web3

from ..utils import normalize_hex, usdc_to_base_units
from .common import console


def load_payload_file(
    payload_file: Path,
    chain: int | None,
    vault: str | None,
    tx: str | None,
    amount: str | None,
    hotkey: str | None,
    slot: int | None,
    miner_evm: str | None,
    password: str | None,
    signature: str | None,
    timestamp: int | None,
) -> tuple[
    int | None,
    str | None,
    str | None,
    str | None,
    int | None,
    str | None,
    int | None,
    str | None,
    str | None,
    str | None,
    int | None,
    str | None,  # pool_id
]:
    """Load and validate payload from file, overriding with CLI args if provided.

    Returns tuple of (chain, vault, tx, amount_str, amount_base_units, hotkey, slot,
                      miner_evm, password, signature, timestamp, lock_days)
    """
    if not payload_file.exists():
        console.print(
            f"[bold red]Error:[/] Payload file not found: {payload_file}"
        )
        raise typer.Exit(code=1)

    try:
        payload_data = json.loads(payload_file.read_text())
    except json.JSONDecodeError as exc:
        console.print(
            f"[bold red]Error:[/] Invalid JSON in payload file: {exc}"
        )
        raise typer.Exit(code=1) from exc

    # Extract values from payload file, using command-line args as overrides
    chain = chain if chain is not None else payload_data.get("chain")
    vault = vault if vault is not None else payload_data.get("vault")
    tx = tx if tx is not None else payload_data.get("tx")

    # Validate extracted values
    if chain is not None:
        try:
            chain = int(chain)
            if chain <= 0:
                console.print(
                    "[bold red]Error:[/] Chain ID must be a positive integer"
                )
                raise typer.Exit(code=1)
        except (ValueError, TypeError):
            console.print(
                "[bold red]Error:[/] Chain ID must be a valid integer"
            )
            raise typer.Exit(code=1) from None
    if vault is not None and not Web3.is_address(vault):
        console.print(
            "[bold red]Error:[/] Vault address must be a valid EVM address"
        )
        raise typer.Exit(code=1)
    if tx is not None:
        tx_normalized = normalize_hex(tx)
        if len(tx_normalized) != 66:
            console.print(
                "[bold red]Error:[/] Transaction hash must be 32 bytes (0x + 64 hex characters)"
            )
            raise typer.Exit(code=1)
        tx = tx_normalized
    # Use amountNormalized if available, otherwise amount (which is in base units)
    if amount is None:
        amount = payload_data.get("amountNormalized") or str(
            payload_data.get("amount", "")
        )
    # Convert amount to base units if it's a normalized string
    amount_base_units: int | None = None
    if amount is not None and amount != "":
        try:
            amount_as_int = int(float(amount))
            if amount_as_int >= 1_000_000_000:  # >= 1e9, likely base units
                amount_base_units = amount_as_int
            else:
                # Treat as normalized USDC
                amount_base_units = usdc_to_base_units(amount)
        except (ValueError, InvalidOperation):
            # If not a valid number, try treating as normalized USDC
            amount_base_units = usdc_to_base_units(amount)
    hotkey = hotkey if hotkey is not None else payload_data.get("hotkey")
    if hotkey is not None:
        if (
            not (hotkey.startswith("bt1") or hotkey.startswith("5"))
            or len(hotkey) < 10
        ):
            console.print(
                "[bold red]Error:[/] Hotkey must be a valid SS58 address (starts with 'bt1' or '5')"
            )
            raise typer.Exit(code=1)

    # Slot is stored as string in JSON, convert to int if loading from file
    if slot is None:
        slot_raw = payload_data.get("slot")
        if slot_raw is not None:
            try:
                slot = int(slot_raw) if isinstance(slot_raw, str) else slot_raw
                if slot < 0:
                    console.print(
                        "[bold red]Error:[/] Slot UID must be a non-negative integer"
                    )
                    raise typer.Exit(code=1)
            except (ValueError, TypeError):
                console.print(
                    "[bold red]Error:[/] Slot UID must be a valid integer"
                )
                raise typer.Exit(code=1) from None

    miner_evm = (
        miner_evm if miner_evm is not None else payload_data.get("miner_evm")
    )
    if miner_evm is not None and not Web3.is_address(miner_evm):
        console.print(
            "[bold red]Error:[/] Miner EVM address must be a valid EVM address"
        )
        raise typer.Exit(code=1)

    password = (
        password if password is not None else payload_data.get("password")
    )
    if password is not None:
        password_normalized = normalize_hex(password)
        if len(password_normalized) != 66:
            console.print(
                "[bold red]Error:[/] Pair password must be 32 bytes (0x + 64 hex characters)"
            )
            raise typer.Exit(code=1)
        password = password_normalized

    signature = (
        signature if signature is not None else payload_data.get("signature")
    )
    if signature is not None:
        signature_normalized = normalize_hex(signature)
        if len(signature_normalized) != 132:
            console.print(
                "[bold red]Error:[/] Signature must be 65 bytes (0x + 130 hex characters)"
            )
            raise typer.Exit(code=1)
        signature = signature_normalized

    timestamp = (
        timestamp if timestamp is not None else payload_data.get("timestamp")
    )

    # Extract pool_id from payload file (used by verifier in demo mode)
    pool_id = payload_data.get("pool_id") or payload_data.get("_demo_pool_id")

    # Validate that all required fields are present
    missing_fields = []
    if chain is None:
        missing_fields.append("chain")
    if vault is None:
        missing_fields.append("vault")
    if tx is None:
        missing_fields.append("tx")
    if amount is None or amount == "":
        missing_fields.append("amount")
    if hotkey is None:
        missing_fields.append("hotkey")
    if slot is None:
        missing_fields.append("slot")
    if miner_evm is None:
        missing_fields.append("miner_evm")
    if password is None:
        missing_fields.append("password")
    if signature is None:
        missing_fields.append("signature")
    if timestamp is None:
        missing_fields.append("timestamp")

    if missing_fields:
        console.print(
            f"[bold red]Error:[/] Payload file is missing required fields: {', '.join(missing_fields)}\n"
            f"Make sure the payload file was generated by build_lock_proof.py"
        )
        raise typer.Exit(code=1)

    console.print(f"[dim]Loaded payload from:[/] {payload_file}")

    return (
        chain,
        vault,
        tx,
        amount,
        amount_base_units,
        hotkey,
        slot,
        miner_evm,
        password,
        signature,
        timestamp,
        pool_id,  # Return pool_id for use in demo mode
    )

