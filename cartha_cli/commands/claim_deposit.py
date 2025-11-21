"""Claim-deposit command - alias for prove-lock."""

from pathlib import Path

import typer

from .prove_lock import prove_lock


def claim_deposit(
    chain: int | None = typer.Option(
        None, "--chain", prompt="Chain ID", show_default=False
    ),
    vault: str | None = typer.Option(
        None, "--vault", prompt="Vault contract address", show_default=False
    ),
    tx: str | None = typer.Option(
        None, "--tx", prompt="Transaction hash", show_default=False
    ),
    amount: int | None = typer.Option(
        None, "--amount", prompt="Lock amount (wei)", show_default=False
    ),
    hotkey: str | None = typer.Option(
        None, "--hotkey", prompt="Hotkey SS58 address", show_default=False
    ),
    slot: int | None = typer.Option(
        None, "--slot", prompt="Slot UID", show_default=False
    ),
    miner_evm: str | None = typer.Option(
        None, "--miner-evm", prompt="Miner EVM address", show_default=False
    ),
    password: str | None = typer.Option(
        None, "--pwd", help="Pair password (0x...)", show_default=False
    ),
    signature: str | None = typer.Option(
        None, "--signature", prompt="EIP-712 signature (0x...)", show_default=False
    ),
    timestamp: int | None = typer.Option(
        None,
        "--timestamp",
        help="Unix timestamp (seconds) used when signing the LockProof. Required when using signature from build_lock_proof.py.",
        show_default=False,
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit the verifier response as JSON."
    ),
) -> None:
    """Alias for prove-lock for deposit-first workflows."""
    # Convert amount from int to str if provided
    amount_str: str | None = None
    if amount is not None:
        amount_str = str(amount)
    prove_lock(
        payload_file=None,
        chain=chain,
        vault=vault,
        tx=tx,
        amount=amount_str,
        hotkey=hotkey,
        slot=slot,
        auto_fetch_uid=True,
        miner_evm=miner_evm,
        password=password,
        signature=signature,
        timestamp=timestamp,
        lock_days=None,
        json_output=json_output,
    )

