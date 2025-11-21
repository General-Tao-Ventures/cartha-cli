"""Extend-lock command - extend lock period by submitting new lock proof with updated lock days."""

from __future__ import annotations

import os
import time
from decimal import Decimal
from typing import Any

import typer
from rich import box
from rich.prompt import Confirm
from rich.table import Table
from web3 import Web3

try:
    from eth_account import Account
except ImportError:
    Account = None  # type: ignore

from ..config import settings
from ..display import display_clock_and_countdown
from ..pair import (
    build_pair_auth_payload,
    get_uid_from_hotkey,
    request_pair_status_or_password,
)
from ..utils import normalize_hex
from ..verifier import VerifierError, extend_lock as verifier_extend_lock
from ..wallet import load_wallet
from .common import console, exit_with_error, handle_unexpected_exception
from .prove_lock_helpers import generate_eip712_signature


def extend_lock(
    wallet_name: str = typer.Option(
        ...,
        "--wallet-name",
        "--wallet.name",
        prompt="Coldkey wallet name",
        help="Coldkey wallet name used for signing.",
        show_default=False,
    ),
    wallet_hotkey: str = typer.Option(
        ...,
        "--wallet-hotkey",
        "--wallet.hotkey",
        prompt="Hotkey name",
        help="Hotkey name used for signing.",
        show_default=False,
    ),
    slot: int | None = typer.Option(
        None,
        "--slot",
        help="Subnet UID assigned to the miner. If not provided, will prompt for input.",
        show_default=False,
    ),
    auto_fetch_uid: bool = typer.Option(
        True,
        "--auto-fetch-uid/--no-auto-fetch-uid",
        help="Automatically fetch UID from Bittensor network (default: enabled). Use --no-auto-fetch-uid to prompt for UID.",
    ),
    network: str = typer.Option(
        settings.network, "--network", help="Bittensor network name."
    ),
    netuid: int = typer.Option(settings.netuid, "--netuid", help="Subnet netuid."),
    lock_days: int | None = typer.Option(
        None,
        "--lock-days",
        help="New lock period in days (min 7, max 365). This will REPLACE your current lock days, not extend them.",
        show_default=False,
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit the verifier response as JSON."
    ),
) -> None:
    """Extend lock period by submitting a new lock proof with updated lock days.
    
    This command allows you to extend your lock period by submitting a new lock proof
    with updated lock days. The new lock days will REPLACE your current lock period
    (calculated from the current time), not extend it.
    
    Requirements:
    - You must have an existing lock proof (use 'cartha pair status' to check)
    - You must have access to the EVM private key used for the original lock
    - You must sign a new EIP-712 signature with the updated lock days
    """
    try:
        console.print("[bold cyan]Loading wallet...[/]")
        wallet = load_wallet(wallet_name, wallet_hotkey, None)
        hotkey = wallet.hotkey.ss58_address

        # Fetch UID automatically by default, prompt if disabled
        if slot is None:
            if auto_fetch_uid:
                console.print("[bold cyan]Fetching UID from subnet...[/]")
                try:
                    slot = get_uid_from_hotkey(
                        network=network, netuid=netuid, hotkey=hotkey
                    )
                    if slot is None:
                        console.print(
                            "[bold yellow]Hotkey is not registered or has been deregistered[/] "
                            f"on netuid {netuid} ({network} network)."
                        )
                        console.print(
                            "[yellow]You do not belong to any UID at the moment.[/] "
                            "Please register your hotkey first using 'cartha register'."
                        )
                        raise typer.Exit(code=0)
                    console.print(f"[bold green]Found UID: {slot}[/]")
                except typer.Exit:
                    raise
                except Exception as exc:
                    console.print(
                        "[bold red]Failed to fetch UID automatically[/]: This may be due to Bittensor network issues."
                    )
                    console.print("[yellow]Falling back to manual input...[/]")
                    try:
                        slot_input = typer.prompt("Enter your slot UID", type=int)
                        slot = slot_input
                        console.print(f"[bold green]Using UID: {slot}[/]")
                    except (ValueError, KeyboardInterrupt):
                        console.print("[bold red]Invalid UID or cancelled.[/]")
                        raise typer.Exit(code=1) from exc
            else:
                console.print(
                    "[bold cyan]UID not provided.[/] "
                    "[yellow]Auto-fetch disabled. Enter UID manually.[/]"
                )
                try:
                    slot_input = typer.prompt(
                        "Enter your slot UID (from 'cartha register' output)", type=int
                    )
                    slot = slot_input
                    console.print(f"[bold green]Using UID: {slot}[/]")
                except (ValueError, KeyboardInterrupt):
                    console.print("[bold red]Invalid UID or cancelled.[/]")
                    raise typer.Exit(code=1)

        # Build authentication payload
        console.print("\n[bold cyan]Signing hotkey ownership challenge...[/]")
        auth_payload = build_pair_auth_payload(
            network=network,
            netuid=netuid,
            slot=str(slot),
            hotkey=hotkey,
            wallet_name=wallet_name,
            wallet_hotkey=wallet_hotkey,
        )

        # Get current lock proof details from verifier
        console.print("\n[bold cyan]Fetching current lock proof details...[/]")
        try:
            status = request_pair_status_or_password(
                mode="status",
                hotkey=hotkey,
                slot=str(slot),
                network=network,
                netuid=netuid,
                auth_payload=auth_payload,
            )
        except VerifierError as exc:
            console.print(f"[bold red]Failed to fetch lock proof[/]: {exc}")
            raise typer.Exit(code=1) from exc

        # Check if miner has a lock proof
        if status.get("state") not in ("verified", "active"):
            console.print(
                "[bold red]No lock proof found[/]: You must have an existing lock proof to extend it."
            )
            console.print(
                "[yellow]Use 'cartha prove-lock' to submit your first lock proof.[/]"
            )
            raise typer.Exit(code=1)

        # Get current lock details
        current_lock_days = status.get("lock_days")
        current_expires_at = status.get("expires_at")
        password = status.get("pwd")

        if not password:
            console.print(
                "[bold red]No pair password found[/]: Cannot extend lock without pair password."
            )
            console.print(
                "[yellow]Use 'cartha pair status' to get your pair password first.[/]"
            )
            raise typer.Exit(code=1)

        # Get lock proof details from status response
        chain = status.get("chain_id")
        vault = status.get("vault_address")
        tx = status.get("tx_hash")
        miner_evm = status.get("miner_evm_address")
        amount_base_units = status.get("verified_lock_amount_base_units")

        if not all([chain, vault, tx, miner_evm, amount_base_units]):
            console.print(
                "[bold red]Missing lock proof details[/]: Cannot extend lock without complete lock proof information."
            )
            console.print(
                "[yellow]This may happen if your lock proof is from an older version. "
                "Please use 'cartha prove-lock' to submit a new lock proof instead.[/]"
            )
            raise typer.Exit(code=1)

        # Normalize addresses and hash
        vault = Web3.to_checksum_address(vault)
        miner_evm = Web3.to_checksum_address(miner_evm)
        tx = normalize_hex(tx.lower())

        # Prompt for new lock days
        if lock_days is None:
            console.print()
            console.print(
                "[bold yellow]⚠ Important:[/] This will REPLACE your current lock days, not extend them."
            )
            if current_lock_days:
                console.print(
                    f"[dim]Current lock days: {current_lock_days}[/]"
                )
            if current_expires_at:
                console.print(
                    f"[dim]Current expiration: {current_expires_at}[/]"
                )
            console.print()
            while True:
                try:
                    lock_days_input = typer.prompt(
                        "New lock period in days (min 7, max 365)",
                        show_default=False,
                    )
                    lock_days = int(lock_days_input)
                    if lock_days < 7 or lock_days > 365:
                        console.print(
                            "[bold red]Error:[/] Lock period must be between 7 and 365 days"
                        )
                        continue
                    break
                except ValueError:
                    console.print(
                        "[bold red]Error:[/] Lock period must be a valid integer"
                    )

        # Collect EVM private key for signing
        console.print("\n[bold cyan]Please provide your EVM private key for signing:[/]")
        private_key_from_env = os.getenv("CARTHA_EVM_PK")
        if private_key_from_env:
            console.print(
                "[dim]Using CARTHA_EVM_PK from environment variable[/]"
            )
        else:
            console.print(
                "[dim]Tip:[/] Set CARTHA_EVM_PK environment variable to avoid prompting"
            )

        while True:
            private_key = (
                private_key_from_env
                if private_key_from_env
                else typer.prompt(
                    "EVM private key (0x...)",
                    hide_input=True,
                    show_default=False,
                )
            )

            try:
                private_key_normalized = normalize_hex(private_key)
                if len(private_key_normalized) != 66:
                    console.print(
                        "[bold red]Error:[/] Private key must be 32 bytes (0x + 64 hex characters)"
                    )
                    if private_key_from_env:
                        private_key_from_env = None
                    continue

                if Account is None:
                    exit_with_error(
                        "eth-account is required for EIP-712 signing. Install it with: uv sync"
                    )
                account = Account.from_key(private_key_normalized)
                derived_evm = Web3.to_checksum_address(account.address)

                console.print(f"\n[bold cyan]Derived EVM address:[/] {derived_evm}")
                if derived_evm.lower() != miner_evm.lower():
                    console.print(
                        f"[yellow]Warning:[/] Derived EVM address ({derived_evm}) "
                        f"does not match lock proof EVM address ({miner_evm})"
                    )
                    if not typer.confirm("Continue anyway?", default=False):
                        if private_key_from_env:
                            private_key_from_env = None
                        continue
                else:
                    console.print("[bold green]✓ EVM address matches[/]")

                miner_evm = derived_evm  # Use derived address
                break
            except Exception as exc:
                console.print(
                    f"[bold red]Error:[/] Failed to derive EVM address: {exc}"
                )
                if private_key_from_env:
                    private_key_from_env = None
                continue

        # Generate new EIP-712 signature with new lock days and current timestamp
        timestamp = int(time.time())
        console.print("\n[dim]Generating EIP-712 signature with new lock days...[/]")
        try:
            lock_proof_signature, derived_evm_str = generate_eip712_signature(
                chain_id=chain,
                vault_address=vault,
                miner_hotkey=hotkey,
                slot_uid=str(slot),
                tx_hash=tx,
                amount=amount_base_units,
                password=password,
                timestamp=timestamp,
                lock_days=lock_days,
                private_key=private_key_normalized,
            )
            derived_evm = Web3.to_checksum_address(derived_evm_str)
            if miner_evm.lower() != derived_evm.lower():
                console.print(
                    f"[yellow]Warning:[/] EVM address mismatch detected. "
                    f"Expected {miner_evm}, got {derived_evm}"
                )
                if not typer.confirm("Continue anyway?", default=False):
                    raise typer.Exit(code=1)
            console.print("[bold green]✓ Signature generated[/]")
        except Exception as exc:
            handle_unexpected_exception("Failed to generate signature", exc)

        # Show summary and confirm
        if not json_output:
            human_amount = Decimal(amount_base_units) / Decimal(10**6)
            amount_str = f"{human_amount:.6f}".rstrip("0").rstrip(".")
            console.print("\n[bold cyan]Lock Extension Summary:[/]")
            summary_table = Table(show_header=False, box=box.SIMPLE)
            summary_table.add_column(style="cyan")
            summary_table.add_column(style="yellow")
            summary_table.add_row("Chain ID", str(chain))
            summary_table.add_row("Vault", vault)
            summary_table.add_row("Transaction", tx)
            summary_table.add_row(
                "Amount", f"{amount_str} USDC ({amount_base_units} base units)"
            )
            summary_table.add_row("Hotkey", hotkey)
            summary_table.add_row("Slot UID", str(slot))
            summary_table.add_row("EVM Address", miner_evm)
            if current_lock_days:
                summary_table.add_row("Current Lock Days", str(current_lock_days))
            summary_table.add_row("New Lock Days", str(lock_days))
            summary_table.add_row(
                "Signature",
                lock_proof_signature[:20] + "..." + lock_proof_signature[-10:],
            )
            console.print(summary_table)
            console.print()
            console.print(
                "[bold yellow]⚠ Important:[/] This will REPLACE your current lock days "
                f"with {lock_days} days, calculated from the current time. "
                "This is NOT an extension/top-up of your existing lock period."
            )
            console.print()
            display_clock_and_countdown()
        else:
            console.print(
                f"[dim]Preparing to submit lock extension: "
                f"chain={chain}, vault={vault}, amount={amount_base_units}, "
                f"hotkey={hotkey}, slot={slot}, new_lock_days={lock_days}[/]"
            )

        if not Confirm.ask(
            "[bold yellow]Submit this lock extension to the verifier?[/]", default=True
        ):
            if json_output:
                import json
                console.print(json.dumps({"ok": False, "cancelled": True}))
            else:
                console.print("[bold yellow]Submission cancelled.[/]")
            raise typer.Exit(code=0)

        # Submit using the new extend-lock endpoint
        try:
            response = verifier_extend_lock(
                auth_payload=auth_payload,
                lock_days=lock_days,
                lock_proof_signature=lock_proof_signature,
                timestamp=timestamp,
            )
        except VerifierError as exc:
            error_msg = str(exc)
            if exc.status_code == 404:
                if "No existing lock proof" in error_msg:
                    console.print(
                        "[bold red]Lock extension rejected[/]: No existing lock proof found."
                    )
                    console.print(
                        "[yellow]Error details[/]: "
                        "You must submit a lock proof first using 'cartha prove-lock'."
                    )
                elif "No pair password" in error_msg:
                    console.print(
                        "[bold red]Lock extension rejected[/]: No pair password found."
                    )
                    console.print(
                        "[yellow]Error details[/]: "
                        "Please register first using 'cartha register' or 'cartha pair status'."
                    )
                else:
                    console.print(f"[bold red]Lock extension rejected[/]: {error_msg}")
            elif exc.status_code == 401:
                console.print(
                    "[bold red]Lock extension rejected[/]: Invalid EIP-712 signature."
                )
                console.print(
                    "[yellow]Error details[/]: "
                    "The signature does not match the lock proof details. "
                    "Make sure you're using the correct EVM private key."
                )
            else:
                console.print(f"[bold red]Lock extension rejected[/]: {error_msg}")
            raise typer.Exit(code=1) from exc

        if json_output:
            from rich.json import JSON
            console.print(JSON.from_data(response))
        else:
            console.print("\n[bold green]✓ Lock extension submitted successfully[/]")
            console.print(
                f"[bold cyan]New lock period[/]: {lock_days} days (replaces previous lock period)"
            )
            console.print(
                "[bold cyan]Reminder[/]: keep your pair password private to prevent USDC theft."
            )
    except typer.Exit:
        raise
    except Exception as exc:
        handle_unexpected_exception("Lock extension failed", exc)


