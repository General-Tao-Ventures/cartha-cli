"""Pair status command."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import bittensor as bt
import typer
from rich.json import JSON
from rich.table import Table

from ..config import settings
from ..display import display_clock_and_countdown
from ..pair import (
    build_pair_auth_payload,
    get_uid_from_hotkey,
    request_pair_status_or_password,
)
from ..utils import format_timestamp
from ..verifier import VerifierError, register_pair_password
from ..wallet import load_wallet
from .common import (
    console,
    handle_unexpected_exception,
    handle_wallet_exception,
)


def pair_status(
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
    json_output: bool = typer.Option(
        False, "--json", help="Emit the raw JSON response."
    ),
) -> None:
    """Show the verifier state for a miner pair.
    
    State Legend:
    ════════════════════════════════════════════════════════════════
    
    1. active   - In current frozen epoch, earning rewards
    
    2. verified - Has lock proof, not in current active epoch
    
    3. pending  - Registered, no lock proof submitted yet
    
    4. revoked  - Revoked (deregistered or evicted)
    
    5. unknown  - No pair record found
    
    ════════════════════════════════════════════════════════════════
    """
    try:
        console.print("[bold cyan]Loading wallet...[/]")
        wallet = load_wallet(wallet_name, wallet_hotkey, None)
        hotkey = wallet.hotkey.ss58_address

        # Fetch UID automatically by default, prompt if disabled
        if slot is None:
            if auto_fetch_uid:
                # Auto-fetch enabled (default) - try to fetch from network
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
                # Auto-fetch disabled (--no-auto-fetch-uid) - prompt for UID
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

        slot_id = str(slot)
        # Skip metagraph check - verifier will validate the pair anyway
        # This avoids slow metagraph() calls that cause timeouts

        console.print("[bold cyan]Signing hotkey ownership challenge...[/]")
        auth_payload = build_pair_auth_payload(
            network=network,
            netuid=netuid,
            slot=slot_id,
            hotkey=hotkey,
            wallet_name=wallet_name,
            wallet_hotkey=wallet_hotkey,
        )
        with console.status(
            "[bold cyan]Verifying ownership with Cartha verifier...[/]",
            spinner="dots",
        ):
            status = request_pair_status_or_password(
                mode="status",
                hotkey=hotkey,
                slot=slot_id,
                network=network,
                netuid=netuid,
                auth_payload=auth_payload,
            )
    except bt.KeyFileError as exc:
        handle_wallet_exception(
            wallet_name=wallet_name, wallet_hotkey=wallet_hotkey, exc=exc
        )
    except typer.Exit:
        raise
    except VerifierError as exc:
        # VerifierError is already handled in _request_pair_status_or_password
        # But if it somehow reaches here, handle it
        error_msg = str(exc)
        if "timed out" in error_msg.lower() or "timeout" in error_msg.lower():
            console.print(f"[bold red]Request timed out[/]")
            # Print the full error message (may be multi-line)
            console.print(f"[yellow]{error_msg}[/]")
        else:
            console.print(f"[bold red]Verifier request failed[/]: {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        # Check if it's a timeout-related error (even if wrapped)
        error_msg = str(exc)
        error_type = type(exc).__name__

        # Check for timeout indicators in the exception
        is_timeout = (
            "timed out" in error_msg.lower()
            or "timeout" in error_msg.lower()
            or error_type == "Timeout"
            or (
                hasattr(exc, "__cause__")
                and exc.__cause__ is not None
                and (
                    "timeout" in str(exc.__cause__).lower()
                    or "Timeout" in type(exc.__cause__).__name__
                )
            )
        )

        if is_timeout:
            console.print(f"[bold red]Request timed out[/]")
            console.print(
                f"[yellow]CLI failed to reach Cartha verifier\n"
                f"Possible causes: Network latency or the verifier is receiving too many requests\n"
                f"Tip: Try again in a moment\n"
                f"Error details: {error_msg}[/]"
            )
            raise typer.Exit(code=1) from exc

        handle_unexpected_exception("Unable to fetch pair status", exc)

    initial_status = dict(status)
    password_payload: dict[str, Any] | None = None

    existing_pwd = initial_status.get("pwd")
    state = initial_status.get("state") or "unknown"
    has_pwd_flag = initial_status.get("has_pwd") or bool(existing_pwd)

    needs_password = state in ("unknown", "pending") and not json_output
    if has_pwd_flag:
        needs_password = False

    if needs_password:
        if state == "unknown":
            console.print(
                "[bold yellow]Verifier has no password record for this slot yet.[/]"
            )
        else:
            console.print(
                "[bold yellow]Pair is registered but no verifier password has been issued yet.[/]"
            )
        if not typer.confirm("Generate a password now?", default=True):
            console.print(
                "[bold yellow]Password generation skipped. Run this command again whenever you're ready.[/]"
            )
            raise typer.Exit(code=0)

        try:
            with console.status(
                "[bold cyan]Requesting password issuance from Cartha verifier...[/]",
                spinner="dots",
            ):
                password_payload = register_pair_password(
                    hotkey=hotkey,
                    slot=slot_id,
                    network=network,
                    netuid=netuid,
                    message=auth_payload["message"],
                    signature=auth_payload["signature"],
                )
        except VerifierError as exc:
            message = str(exc)
            if exc.status_code == 504 or "timeout" in message.lower():
                console.print(
                    "[bold yellow]Password generation timed out[/]: run 'cartha pair status' again in ~1 minute."
                )
            else:
                console.print(f"[bold red]Password generation failed[/]: {message}")
            raise typer.Exit(code=1) from None
        except typer.Exit:
            raise
        except Exception as exc:
            handle_unexpected_exception(
                "Verifier password generation failed unexpectedly", exc
            )

        console.print("[bold green]Pair password issued.[/]")

        try:
            with console.status(
                "[bold cyan]Refreshing verifier status...[/]",
                spinner="dots",
            ):
                status = request_pair_status_or_password(
                    mode="status",
                    hotkey=hotkey,
                    slot=slot_id,
                    network=network,
                    netuid=netuid,
                    auth_payload=auth_payload,
                )
        except VerifierError as exc:
            console.print(f"[bold yellow]Unable to refresh pair status[/]: {exc}")
            status = initial_status
            if state == "unknown":
                status["state"] = "pending"
            status["has_pwd"] = bool(password_payload and password_payload.get("pwd"))
            if password_payload:
                status["pwd"] = password_payload.get("pwd")
                status["issued_at"] = password_payload.get("issued_at") or status.get(
                    "issued_at"
                )

    sanitized = dict(status)
    sanitized.setdefault("state", "unknown")
    sanitized["hotkey"] = hotkey
    sanitized["slot"] = slot_id
    password = sanitized.get("pwd")

    if json_output:
        console.print(JSON.from_data(sanitized))
        if password:
            console.print(
                "[bold yellow]Keep it safe[/] — for your eyes only. Exposure might allow others to steal your locked USDC rewards."
            )
        return

    # Display clock and countdown
    display_clock_and_countdown()

    table = Table(title="Pair Status", show_header=False)
    table.add_row("Hotkey", hotkey)
    table.add_row("Slot UID", slot_id)
    table.add_row("State", sanitized["state"])

    # Show lock amounts for verified/active states
    state = sanitized.get("state", "").lower()
    if state in ("verified", "active"):
        # Show active amount (from last frozen epoch - currently earning rewards)
        active_amount_usdc = sanitized.get("active_lock_amount_usdc")
        verified_amount_usdc = sanitized.get("verified_lock_amount_usdc")
        
        if active_amount_usdc is not None:
            amount_str = f"{active_amount_usdc:.6f}".rstrip("0").rstrip(".")
            table.add_row("Active lock amount", f"{amount_str} USDC [dim](currently earning)[/]")
        
        # Show verified amount (from upcoming epoch - will earn rewards next week)
        if verified_amount_usdc is not None:
            amount_str = f"{verified_amount_usdc:.6f}".rstrip("0").rstrip(".")
            # Only show if different from active amount, or if active amount is None
            if active_amount_usdc is None or verified_amount_usdc != active_amount_usdc:
                table.add_row("Verified lock amount", f"{amount_str} USDC [dim](next epoch)[/]")

        # Show lock days and expiration
        lock_days = sanitized.get("lock_days")
        if lock_days is not None:
            table.add_row("Lock days", str(lock_days))

        expires_at = sanitized.get("expires_at")
        if expires_at is not None:
            # Format expiration datetime (date + time for urgency)
            try:
                if isinstance(expires_at, str):
                    # Parse ISO format datetime string
                    dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    formatted_expires = format_timestamp(dt.timestamp())
                elif isinstance(expires_at, datetime):
                    formatted_expires = format_timestamp(expires_at.timestamp())
                else:
                    formatted_expires = str(expires_at)
                table.add_row("Expires at", formatted_expires)
            except Exception:
                table.add_row("Expires at", str(expires_at))

    table.add_row("Password issued", "yes" if sanitized.get("has_pwd") else "no")
    issued_at = sanitized.get("issued_at")
    if issued_at:
        # Try to parse and format the timestamp
        try:
            if isinstance(issued_at, (int, float)) or (
                isinstance(issued_at, str) and issued_at.isdigit()
            ):
                # Numeric timestamp
                formatted_time = format_timestamp(issued_at)
            elif isinstance(issued_at, str):
                # Try parsing as ISO format datetime string
                try:
                    dt = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                    timestamp = dt.timestamp()
                    formatted_time = format_timestamp(timestamp)
                except (ValueError, AttributeError):
                    # If parsing fails, display as-is
                    formatted_time = issued_at
            else:
                formatted_time = str(issued_at)
            table.add_row("Password issued at", formatted_time)
        except Exception:
            table.add_row("Password issued at", str(issued_at))
    if password:
        table.add_row("Pair password", password)
    console.print(table)

    # Show warnings and reminders
    if password:
        console.print()
        console.print(
            "[bold yellow]🔐 Keep your password safe[/] — Exposure might allow others to steal your locked USDC rewards."
        )

    # Show detailed status information for verified/active pairs
    if state in ("verified", "active"):
        in_upcoming_epoch = sanitized.get("in_upcoming_epoch")
        expires_at = sanitized.get("expires_at")

        console.print()
        console.print("[bold cyan]━━━ Epoch Status ━━━[/]")

        # Upcoming epoch inclusion status
        if in_upcoming_epoch:
            console.print(
                "[bold green]✓ Included in upcoming epoch[/] — You will receive rewards for the next epoch."
            )
        elif in_upcoming_epoch is False:
            console.print(
                "[bold yellow]⚠ Not included in upcoming epoch[/] — Use [bold]cartha prove-lock[/] to be included."
            )

        # Expiration date information and warnings
        if expires_at:
            try:
                # Parse expiration datetime
                if isinstance(expires_at, str):
                    exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                elif isinstance(expires_at, datetime):
                    exp_dt = expires_at
                else:
                    exp_dt = None

                if exp_dt:
                    now = datetime.now(UTC)
                    time_until_expiry = (exp_dt - now).total_seconds()
                    days_until_expiry = time_until_expiry / 86400

                    console.print()
                    console.print("[bold cyan]━━━ Lock Expiration ━━━[/]")

                    if days_until_expiry < 0:
                        console.print(
                            "[bold red]⚠ EXPIRED[/] — Lock expired. USDC will be returned. No more emissions."
                        )
                    elif days_until_expiry <= 7:
                        console.print(
                            f"[bold red]⚠ Expiring in {days_until_expiry:.1f} days[/] — Make a new lock transaction on-chain to continue receiving emissions."
                        )
                    elif days_until_expiry <= 30:
                        console.print(
                            f"[bold yellow]⚠ Expiring in {days_until_expiry:.0f} days[/] — Consider making a new lock transaction on-chain soon."
                        )
                    else:
                        console.print(
                            f"[bold green]✓ Valid for {days_until_expiry:.0f} days[/]"
                        )
            except Exception:
                pass

        # Concise reminder
        console.print()
        console.print("[bold cyan]━━━ Reminders ━━━[/]")
        console.print("• Lock expiration: USDC returned automatically, emissions stop.")
        console.print(
            "• Top-ups/extensions: Happen automatically on-chain. No CLI action needed."
        )

    # Explicitly return to ensure clean exit
    return
