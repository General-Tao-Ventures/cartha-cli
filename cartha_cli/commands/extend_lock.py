"""Extend-lock command - extend lock period by updating lock days.
    
Simplified to only require Bittensor signature for hotkey ownership.
All lock proof details are retrieved from the database.
"""

from __future__ import annotations

from typing import Any

import typer
from rich import box
from rich.prompt import Confirm
from rich.table import Table


from ..config import settings
from ..display import display_clock_and_countdown
from ..pair import (
    build_pair_auth_payload,
    get_uid_from_hotkey,
    request_pair_status_or_password,
)
from ..verifier import VerifierError, extend_lock as verifier_extend_lock
from ..wallet import load_wallet
from .common import console, handle_unexpected_exception


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

        # Show summary and confirm
        if not json_output:
            console.print("\n[bold cyan]Lock Extension Summary:[/]")
            summary_table = Table(show_header=False, box=box.SIMPLE)
            summary_table.add_column(style="cyan")
            summary_table.add_column(style="yellow")
            summary_table.add_row("Hotkey", hotkey)
            summary_table.add_row("Slot UID", str(slot))
            if current_lock_days:
                summary_table.add_row("Current Lock Days", str(current_lock_days))
            summary_table.add_row("New Lock Days", str(lock_days))
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

        # Submit using the simplified extend-lock endpoint
        try:
            response = verifier_extend_lock(
                hotkey=hotkey,
                slot=str(slot),
                network=network,
                netuid=netuid,
                message=auth_payload["message"],
                signature=auth_payload["signature"],
                lock_days=lock_days,
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


