"""Miner password command - shows password with authentication."""

from __future__ import annotations

from typing import Any

import bittensor as bt
import typer
from rich.json import JSON

from ..config import settings
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


def miner_password(
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
        help="Automatically fetch UID from Bittensor network (default: enabled).",
        show_default=False,
    ),
    network: str = typer.Option(
        settings.network, "--network", help="Bittensor network name."
    ),
    netuid: int = typer.Option(settings.netuid, "--netuid", help="Subnet netuid."),
    json_output: bool = typer.Option(
        False, "--json", help="Emit the raw JSON response."
    ),
) -> None:
    """Show your miner password (requires authentication).

    This command requires signing a challenge message to prove ownership.
    If no password exists, you'll be prompted to create one.
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
                            "Please register your hotkey first using 'cartha miner register'."
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
                        "Enter your slot UID (from 'cartha miner register' output)",
                        type=int,
                    )
                    slot = slot_input
                    console.print(f"[bold green]Using UID: {slot}[/]")
                except (ValueError, KeyboardInterrupt):
                    console.print("[bold red]Invalid UID or cancelled.[/]")
                    raise typer.Exit(code=1)

        slot_id = str(slot)

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
        error_msg = str(exc)
        if "timed out" in error_msg.lower() or "timeout" in error_msg.lower():
            console.print(f"[bold red]Request timed out[/]")
            console.print(f"[yellow]{error_msg}[/]")
        else:
            console.print(f"[bold red]Verifier request failed[/]: {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        error_msg = str(exc)
        error_type = type(exc).__name__

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

        handle_unexpected_exception("Unable to fetch password", exc)

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
                    "[bold yellow]Password generation timed out[/]: run 'cartha miner password' again in ~1 minute."
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
                "[bold cyan]Refreshing password...[/]",
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
            console.print(f"[bold yellow]Unable to refresh password[/]: {exc}")
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
    password = sanitized.get("pwd")
    issued_at = sanitized.get("issued_at")

    if json_output:
        console.print(JSON.from_data(sanitized))
        if password:
            console.print(
                "[bold yellow]Keep it safe[/] — for your eyes only. Exposure might allow others to steal your locked USDC rewards."
            )
        return

    # Display password information
    from rich.table import Table
    from datetime import datetime

    table = Table(title="Miner Password", show_header=False)
    table.add_row("Hotkey", hotkey)
    table.add_row("Slot UID", slot_id)
    table.add_row("Password issued", "yes" if sanitized.get("has_pwd") else "no")

    if issued_at:
        try:
            if isinstance(issued_at, (int, float)) or (
                isinstance(issued_at, str) and issued_at.isdigit()
            ):
                formatted_time = format_timestamp(issued_at)
            elif isinstance(issued_at, str):
                try:
                    dt = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                    timestamp = dt.timestamp()
                    formatted_time = format_timestamp(timestamp)
                except (ValueError, AttributeError):
                    formatted_time = issued_at
            else:
                formatted_time = str(issued_at)
            table.add_row("Password issued at", formatted_time)
        except Exception:
            table.add_row("Password issued at", str(issued_at))

    if password:
        table.add_row("Pair password", password)

    console.print(table)

    # Show password warning
    if password:
        console.print()
        console.print(
            "[bold yellow]🔐 Keep your password safe[/] — Exposure might allow others to steal your locked USDC rewards."
        )

    return
