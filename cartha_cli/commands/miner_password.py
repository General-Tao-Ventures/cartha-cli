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
)
from ..utils import format_timestamp
from ..verifier import VerifierError, fetch_pair_status
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
    """DEPRECATED: View your existing miner password (requires authentication).

    ⚠️  This command is deprecated. The new lock flow uses session tokens instead of passwords.
    Passwords were only used in the old LockProof flow, which has been replaced.

    This command allows you to VIEW existing passwords only. Password generation is no longer supported.
    Use 'cartha vault lock' to create new lock positions with the new flow.
    """
    console.print(
        "[bold yellow]⚠️  DEPRECATED:[/] The miner password command is deprecated. "
        "The new lock flow uses session tokens instead of passwords."
    )
    console.print()
    console.print(
        "[dim]This command allows you to VIEW existing passwords only. "
        "Password generation is no longer supported.[/]"
    )
    console.print()
    
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
            status = fetch_pair_status(
                hotkey=hotkey,
                slot=slot_id,
                network=network,
                netuid=netuid,
                message=auth_payload["message"],
                signature=auth_payload["signature"],
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
    existing_pwd = initial_status.get("pwd")
    state = initial_status.get("state") or "unknown"
    has_pwd_flag = initial_status.get("has_pwd") or bool(existing_pwd)

    # Password generation is deprecated - only allow viewing existing passwords
    if not has_pwd_flag and not json_output:
        console.print()
        console.print(
            "[bold yellow]⚠️  No password found for this miner.[/]"
        )
        console.print()
        console.print(
            "[dim]Password generation is no longer supported. "
            "The new lock flow uses session tokens instead of passwords.[/]"
        )
        console.print()
        console.print(
            "[bold cyan]To create a lock position, use the new lock flow:[/]"
        )
        console.print("  [green]cartha vault lock[/] --coldkey <name> --hotkey <name> --pool-id <pool> --amount <amount> --lock-days <days> --owner-evm <address> --chain-id <chain> --vault-address <vault>")
        console.print()
        raise typer.Exit(code=0)

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
