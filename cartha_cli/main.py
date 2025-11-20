"""Primary Typer application for the Cartha CLI."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from decimal import ROUND_DOWN, Decimal, InvalidOperation
from pathlib import Path
from typing import Any, NoReturn
from zoneinfo import ZoneInfo

import bittensor as bt
import typer
from rich import box
from rich.console import Console
from rich.json import JSON
from rich.prompt import Confirm
from rich.rule import Rule
from rich.table import Table
from web3 import Web3

try:
    from eth_account import Account
except ImportError:
    Account = None  # type: ignore

from .bt import (
    RegistrationResult,
    get_burn_cost,
    get_subtensor,
    get_wallet,
    register_hotkey,
)
from .config import settings
from .eth712 import LockProofMessage
from .verifier import (
    VerifierError,
    fetch_pair_password,
    fetch_pair_status,
    register_pair_password,
    submit_lock_proof,
)

CHALLENGE_PREFIX = "cartha-pair-auth"
CHALLENGE_TTL_SECONDS = 120

console = Console()


app = typer.Typer(
    help="Miner-facing tooling for registering on the Cartha subnet, managing pair passwords, and submitting lock proofs.",
    add_completion=False,
)
pair_app = typer.Typer(help="Pair status commands.")

app.add_typer(pair_app, name="pair")

_TRACE_ENABLED = False


def _set_trace_enabled(enabled: bool) -> None:
    global _TRACE_ENABLED
    _TRACE_ENABLED = enabled


def _trace_enabled() -> bool:
    return _TRACE_ENABLED


def _exit_with_error(message: str, code: int = 1) -> NoReturn:
    console.print(f"[bold red]{message}[/]")
    raise typer.Exit(code=code)


def _handle_wallet_exception(
    *,
    wallet_name: str | None,
    wallet_hotkey: str | None,
    exc: Exception,
) -> None:
    detail = str(exc).strip()
    name = wallet_name or "<unknown>"
    hotkey = wallet_hotkey or "<unknown>"
    message = (
        f"Unable to open coldkey '{name}' hotkey '{hotkey}'. "
        "Ensure the wallet exists, hotkey files are present, and the key is unlocked."
    )
    if detail:
        message += f" ({detail})"
    _exit_with_error(message)


def _handle_unexpected_exception(context: str, exc: Exception) -> None:
    if _trace_enabled():
        raise
    detail = str(exc).strip()
    message = context
    if detail:
        message += f" ({detail})"
    _exit_with_error(message)


def _normalize_hex(value: str, prefix: str = "0x") -> str:
    """Normalize hex string to ensure it has the correct prefix."""
    value = value.strip()
    if not value.startswith(prefix):
        value = prefix + value
    return value


def _format_timestamp(ts: int | float | str | None) -> str:
    """Format a timestamp showing both UTC and local time.

    Args:
        ts: Unix timestamp (seconds) as int, float, or string, or None for current time

    Returns:
        Formatted string like "2024-01-01 12:00:00 UTC (2024-01-01 07:00:00 EST)"
    """
    if ts is None:
        ts = time.time()
    elif isinstance(ts, str):
        try:
            ts = float(ts)
        except ValueError:
            return str(ts)  # Return as-is if not parseable

    try:
        ts_float = float(ts)
        utc_dt = datetime.fromtimestamp(ts_float, tz=UTC)

        # Get local timezone
        try:
            local_tz: ZoneInfo = ZoneInfo("local")
        except Exception:
            # Fallback if zoneinfo fails (shouldn't happen on Python 3.11+)
            fallback_tz = datetime.now().astimezone().tzinfo
            if fallback_tz is None:
                # Ultimate fallback to UTC
                local_tz = ZoneInfo("UTC")
            else:
                # Type ignore: mypy doesn't understand that ZoneInfo is compatible with tzinfo
                local_tz = fallback_tz  # type: ignore[assignment]

        local_dt = utc_dt.astimezone(local_tz)

        # Format both times
        utc_str = utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        local_str = local_dt.strftime("%Y-%m-%d %H:%M:%S %Z")

        return f"{utc_str} ({local_str})"
    except (ValueError, OSError, OverflowError):
        # Fallback to simple ISO format if anything fails
        try:
            return datetime.fromtimestamp(float(ts), tz=UTC).isoformat()
        except Exception:
            return str(ts)


def _usdc_to_base_units(value: str) -> int:
    try:
        decimal_value = Decimal(value.strip())
    except (InvalidOperation, AttributeError) as exc:
        _exit_with_error("Lock amount must be numeric.")
        raise typer.Exit() from exc  # pragma: no cover
    if decimal_value <= 0:
        _exit_with_error("Lock amount must be positive.")
    quantized = decimal_value.quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
    return int(quantized * Decimal(10**6))


def _get_current_epoch_start(reference: datetime | None = None) -> datetime:
    """Calculate the start of the current epoch (Friday 00:00 UTC).

    Args:
        reference: Reference datetime (defaults to now in UTC)

    Returns:
        Datetime of the current epoch start (Friday 00:00 UTC)
    """
    reference = reference or datetime.now(tz=UTC)
    weekday = reference.weekday()  # Monday=0, Friday=4
    days_since_friday = (weekday - 4) % 7
    candidate = datetime(
        year=reference.year,
        month=reference.month,
        day=reference.day,
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
        tzinfo=UTC,
    )
    return candidate - timedelta(days=days_since_friday)


def _get_next_epoch_freeze_time(reference: datetime | None = None) -> datetime:
    """Calculate the next epoch freeze time (next Friday 00:00 UTC).

    Args:
        reference: Reference datetime (defaults to now in UTC)

    Returns:
        Datetime of the next epoch freeze (next Friday 00:00 UTC)
    """
    current_start = _get_current_epoch_start(reference)
    # If we're exactly at epoch start, next is in 7 days
    # Otherwise, next is current + 7 days
    return current_start + timedelta(days=7)


def _format_countdown(seconds: float) -> str:
    """Format seconds into a human-readable countdown string.

    Args:
        seconds: Number of seconds remaining

    Returns:
        Formatted string like "2d 5h 30m 15s"
    """
    if seconds < 0:
        return "0s"

    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)


def _get_local_timezone() -> ZoneInfo:
    """Get the local timezone, with fallbacks.

    Returns:
        ZoneInfo object for local timezone
    """
    try:
        return ZoneInfo("local")
    except Exception:
        fallback_tz = datetime.now().astimezone().tzinfo
        if fallback_tz is None:
            return ZoneInfo("UTC")
        return fallback_tz  # type: ignore[return-value]


def _get_clock_table() -> Table:
    """Create a table with current time (UTC and local) and countdown to next epoch freeze.

    Returns:
        Table with clock and countdown information
    """
    now_utc = datetime.now(tz=UTC)
    local_tz = _get_local_timezone()
    now_local = now_utc.astimezone(local_tz)

    # Format current time
    utc_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    local_str = now_local.strftime("%Y-%m-%d %H:%M:%S %Z")

    # Calculate next epoch freeze
    next_freeze_utc = _get_next_epoch_freeze_time(now_utc)
    next_freeze_local = next_freeze_utc.astimezone(local_tz)

    # Calculate countdown
    time_until_freeze = (next_freeze_utc - now_utc).total_seconds()
    countdown_str = _format_countdown(time_until_freeze)

    # Format next freeze times
    next_freeze_utc_str = next_freeze_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
    next_freeze_local_str = next_freeze_local.strftime("%Y-%m-%d %H:%M:%S %Z")

    # Create table
    clock_table = Table(show_header=False, box=box.SIMPLE)
    clock_table.add_column(style="cyan")
    clock_table.add_column(style="yellow")

    clock_table.add_row("Current time (UTC)", utc_str)
    clock_table.add_row("Current time (Local)", local_str)
    clock_table.add_row("", "")  # Spacer
    clock_table.add_row("Next epoch freeze (UTC)", next_freeze_utc_str)
    clock_table.add_row("Next epoch freeze (Local)", next_freeze_local_str)
    clock_table.add_row("Countdown", countdown_str)

    return clock_table


def _display_clock_and_countdown() -> None:
    """Display current time (UTC and local) and countdown to next epoch freeze."""
    clock_table = _get_clock_table()
    console.print(clock_table)
    console.print()


def _print_root_help() -> None:
    console.print(Rule("[bold cyan]Cartha CLI[/]"))
    console.print(
        "Miner-facing command line tool for Cartha subnet miners.\n"
        "Authenticate against the verifier, inspect pair status, and submit LockProof payloads."
    )
    console.print()
    console.print("[bold]Usage[/]: cartha [OPTIONS] COMMAND [ARGS]...")
    console.print()

    options = Table(title="Options", box=box.SQUARE_DOUBLE_HEAD, show_header=False)
    options.add_row("[cyan]-h[/], [cyan]--help[/]", "Show this message and exit.")
    console.print(options)
    console.print()

    commands = Table(title="Commands", box=box.SQUARE_DOUBLE_HEAD, show_header=False)
    commands.add_row("[green]version[/]", "Show CLI version.")
    commands.add_row(
        "[green]register[/]", "Register a hotkey and fetch the pair password."
    )
    commands.add_row(
        "[green]pair status[/]", "Sign a challenge and display pair metadata."
    )
    commands.add_row(
        "[green]prove-lock[/]", "Submit an externally signed LockProof payload."
    )
    commands.add_row(
        "[green]claim-deposit[/]", "Alias for prove-lock (deposit-first flow)."
    )
    console.print(commands)
    console.print()

    # Display clock and countdown in a separate table
    clock_table = _get_clock_table()
    console.print(clock_table)
    console.print()

    console.print("[dim]Made with ❤ by GTV[/]")


def _log_endpoint_banner() -> None:
    verifier_url = settings.verifier_url.lower()
    if verifier_url.startswith("http://127.0.0.1"):
        console.print("[bold cyan]Using local verifier endpoint[/]")
    elif "cartha-verifier-826542474079.us-central1.run.app" in verifier_url:
        console.print("[bold cyan]Using Cartha Testnet Verifier[/]")
    else:
        console.print("[bold cyan]Using Cartha network verifier[/]")


@app.callback(invoke_without_command=True)
def cli_root(
    ctx: typer.Context,
    help_option: bool = typer.Option(
        False,
        "--help",
        "-h",
        help="Show this message and exit.",
        is_eager=True,
    ),
    trace: bool = typer.Option(
        False,
        "--trace",
        help="Show full stack traces when errors occur.",
    ),
) -> None:
    """Top-level callback to provide rich help and endpoint banner."""
    _set_trace_enabled(trace)
    if ctx.obj is None:
        ctx.obj = {}
    ctx.obj["trace"] = trace

    if help_option:
        _print_root_help()
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        _print_root_help()
        raise typer.Exit()

    _log_endpoint_banner()


@app.command()
def version() -> None:
    """Print the CLI version."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        console.print(f"[bold white]cartha-cli[/] {version('cartha-cli')}")
    except PackageNotFoundError:  # pragma: no cover
        console.print("[bold white]cartha-cli[/] 0.0.0")


def _get_uid_from_hotkey(
    *,
    network: str,
    netuid: int,
    hotkey: str,
) -> int | None:
    """Get the UID for a hotkey on the subnet.

    Args:
        network: Bittensor network name
        netuid: Subnet netuid
        hotkey: Hotkey SS58 address

    Returns:
        UID if registered, None if not registered or deregistered
    """
    subtensor = None

    try:
        subtensor = get_subtensor(network)

        # Try to get UID directly - if successful, they're registered
        # No need to check is_hotkey_registered() first (redundant)
        # No need for metagraph() fallback (too slow, causes timeouts)
        try:
            uid = subtensor.get_uid_for_hotkey_on_subnet(
                hotkey_ss58=hotkey, netuid=netuid
            )
            if uid is not None and uid >= 0:
                return int(uid)
        except AttributeError:
            # Method doesn't exist in this bittensor version
            # Return None rather than falling back to slow metagraph()
            return None
        except Exception:
            # Any other error means not registered or network issue
            return None

        return None
    except Exception as exc:
        error_msg = str(exc)
        if "nodename" in error_msg.lower() or "servname" in error_msg.lower():
            console.print(
                f"[bold red]Network error[/]: Unable to connect to Bittensor {network} network: {error_msg}"
            )
            console.print(
                "[yellow]This might be a DNS/network connectivity issue. Please check your internet connection.[/]"
            )
            raise typer.Exit(code=1) from None
        # Re-raise other exceptions as-is
        raise
    finally:
        # Clean up connections
        try:
            if subtensor is not None:
                if hasattr(subtensor, "close"):
                    subtensor.close()
                del subtensor
        except Exception:
            pass


def _ensure_pair_registered(
    *,
    network: str,
    netuid: int,
    slot: str,
    hotkey: str,
) -> None:
    subtensor = None
    metagraph = None
    try:
        subtensor = get_subtensor(network)
        metagraph = subtensor.metagraph(netuid)
        slot_index = int(slot)
        if slot_index < 0 or slot_index >= len(metagraph.hotkeys):
            console.print(
                f"[bold red]UID {slot} not found[/] in the metagraph (netuid {netuid})."
            )
            raise typer.Exit(code=1)
        registered_hotkey = metagraph.hotkeys[slot_index]
        if registered_hotkey != hotkey:
            console.print(
                f"[bold red]UID mismatch[/]: slot {slot} belongs to a different hotkey, not {hotkey}. Please verify your inputs."
            )
            raise typer.Exit(code=1)
    except Exception as exc:
        error_msg = str(exc)
        if "nodename" in error_msg.lower() or "servname" in error_msg.lower():
            console.print(
                f"[bold red]Network error[/]: Unable to connect to Bittensor {network} network: {error_msg}"
            )
            console.print(
                "[yellow]This might be a DNS/network connectivity issue. Please check your internet connection.[/]"
            )
            raise typer.Exit(code=1) from None
        # Re-raise other exceptions as-is
        raise
    finally:
        # Clean up connections to prevent hanging
        # Bittensor subtensor objects maintain persistent connections that need explicit cleanup
        try:
            if metagraph is not None:
                # Clean up metagraph reference first
                del metagraph
        except Exception:
            pass
        try:
            if subtensor is not None:
                # Try to close the subtensor connection if the method exists
                if hasattr(subtensor, "close"):
                    subtensor.close()
                # Force cleanup by deleting reference to release connections
                del subtensor
        except Exception:
            # Ignore cleanup errors - connections will be garbage collected eventually
            pass


def _load_wallet(
    wallet_name: str, wallet_hotkey: str, expected_hotkey: str | None
) -> bt.wallet:
    try:
        wallet = get_wallet(wallet_name, wallet_hotkey)
    except bt.KeyFileError as exc:
        _handle_wallet_exception(
            wallet_name=wallet_name, wallet_hotkey=wallet_hotkey, exc=exc
        )
    except Exception as exc:  # pragma: no cover - defensive
        _handle_unexpected_exception(
            f"Failed to load wallet '{wallet_name}/{wallet_hotkey}'", exc
        )

    if expected_hotkey and wallet.hotkey.ss58_address != expected_hotkey:
        _exit_with_error(
            "Hotkey mismatch: loaded wallet hotkey does not match the supplied address."
        )

    return wallet


def _build_pair_auth_payload(
    *,
    network: str,
    netuid: int,
    slot: str,
    hotkey: str,
    wallet_name: str,
    wallet_hotkey: str,
    skip_metagraph_check: bool = False,
) -> dict[str, Any]:
    wallet = _load_wallet(wallet_name, wallet_hotkey, hotkey)
    if not skip_metagraph_check:
        _ensure_pair_registered(
            network=network, netuid=netuid, slot=slot, hotkey=hotkey
        )

    timestamp = int(time.time())
    message = (
        f"{CHALLENGE_PREFIX}|network:{network}|netuid:{netuid}|slot:{slot}|"
        f"hotkey:{hotkey}|ts:{timestamp}"
    )
    message_bytes = message.encode("utf-8")
    signature_bytes = wallet.hotkey.sign(message_bytes)

    verifier_keypair = bt.Keypair(ss58_address=hotkey)
    if not verifier_keypair.verify(message_bytes, signature_bytes):
        console.print("[bold red]Unable to verify the ownership signature locally.[/]")
        raise typer.Exit(code=1)

    expires_at = timestamp + CHALLENGE_TTL_SECONDS
    expiry_time = _format_timestamp(expires_at)
    console.print(
        "[bold green]Ownership challenge signed[/] "
        f"(expires in {CHALLENGE_TTL_SECONDS}s at {expiry_time})."
    )

    return {
        "message": message,
        "signature": "0x" + signature_bytes.hex(),
        "expires_at": expires_at,
    }


def _request_pair_status_or_password(
    *,
    mode: str,
    hotkey: str,
    slot: str,
    network: str,
    netuid: int,
    auth_payload: dict[str, Any],
) -> dict[str, Any]:
    request_kwargs = {
        "hotkey": hotkey,
        "slot": slot,
        "network": network,
        "netuid": netuid,
        "message": auth_payload["message"],
        "signature": auth_payload["signature"],
    }
    try:
        if mode == "status":
            return fetch_pair_status(**request_kwargs)
        if mode == "password":
            return fetch_pair_password(**request_kwargs)
    except VerifierError as exc:
        # Check if it's a timeout error
        error_msg = str(exc)
        if "timed out" in error_msg.lower() or "timeout" in error_msg.lower():
            console.print(f"[bold red]Request timed out[/]")
            # Print the full error message (may be multi-line)
            console.print(f"[yellow]{error_msg}[/]")
        else:
            console.print(f"[bold red]Verifier request failed[/]: {exc}")
        raise typer.Exit(code=1) from exc
    raise RuntimeError(f"Unknown mode {mode}")  # pragma: no cover


@app.command("register")
def register(
    network: str = typer.Option(
        settings.network, "--network", help="Bittensor network name."
    ),
    wallet_name: str = typer.Option(
        None,
        "--wallet-name",
        "--wallet.name",
        prompt="Coldkey wallet name",
        help="Coldkey wallet name.",
        show_default=False,
    ),
    wallet_hotkey: str = typer.Option(
        None,
        "--wallet-hotkey",
        "--wallet.hotkey",
        prompt="Hotkey name",
        help="Hotkey name.",
        show_default=False,
    ),
    netuid: int = typer.Option(settings.netuid, "--netuid", help="Subnet netuid."),
    burned: bool = typer.Option(
        True,
        "--burned/--pow",
        help="Burned registration by default; pass --pow to run PoW registration.",
    ),
    cuda: bool = typer.Option(
        False, "--cuda", help="Enable CUDA for PoW registration."
    ),
) -> None:
    """Register the specified hotkey on the target subnet and print the UID."""

    assert wallet_name is not None  # nosec - enforced by Typer prompt
    assert wallet_hotkey is not None  # nosec - enforced by Typer prompt

    # Initialize subtensor and wallet to get info before registration
    try:
        subtensor = get_subtensor(network)
        wallet = get_wallet(wallet_name, wallet_hotkey)
    except bt.KeyFileError as exc:
        _handle_wallet_exception(
            wallet_name=wallet_name, wallet_hotkey=wallet_hotkey, exc=exc
        )
    except typer.Exit:
        raise
    except Exception as exc:
        _handle_unexpected_exception("Failed to initialize wallet/subtensor", exc)

    hotkey_ss58 = wallet.hotkey.ss58_address
    coldkey_ss58 = wallet.coldkeypub.ss58_address

    # Check if already registered
    if subtensor.is_hotkey_registered(hotkey_ss58, netuid=netuid):
        neuron = subtensor.get_neuron_for_pubkey_and_subnet(hotkey_ss58, netuid)
        uid = (
            None if getattr(neuron, "is_null", False) else getattr(neuron, "uid", None)
        )
        if uid is not None:
            console.print(f"[bold yellow]Hotkey already registered[/]. UID: {uid}")
            return

    # Get registration cost and balance
    registration_cost = None
    balance = None

    if burned:
        try:
            registration_cost = get_burn_cost(network, netuid)
        except Exception as exc:
            # Log warning but continue - cost may not be available on all networks
            console.print(
                f"[bold yellow]Warning: Could not fetch registration cost[/]: {exc}"
            )

    try:
        balance_obj = subtensor.get_balance(coldkey_ss58)
        # Convert Balance object to float using .tao property
        balance = balance_obj.tao if hasattr(balance_obj, "tao") else float(balance_obj)
    except Exception:
        pass

    # Display registration summary table (like btcli)
    console.print(f"[bold]Using the wallet path from config:[/] {wallet.path}")

    summary_table = Table(title="Registration Summary")
    summary_table.add_column("Field", style="cyan")
    summary_table.add_column("Value", style="yellow")

    summary_table.add_row("Netuid", str(netuid))
    if burned:
        if registration_cost is not None:
            summary_table.add_row("Cost", f"τ {registration_cost:.4f}")
        else:
            summary_table.add_row("Cost", "Unable to fetch")
    summary_table.add_row("Hotkey", hotkey_ss58)
    summary_table.add_row("Coldkey", coldkey_ss58)
    summary_table.add_row("Network", network)

    console.print(summary_table)

    # Display balance and cost (already converted to float above)
    if balance is not None:
        console.print(f"\n[bold]Your balance is:[/] {balance:.4f} τ")

    if registration_cost is not None:
        console.print(
            f"[bold]The cost to register by recycle is[/] {registration_cost:.4f} τ"
        )

    # Display clock and countdown
    console.print()
    _display_clock_and_countdown()

    # Confirmation prompt
    if not typer.confirm("\nDo you want to continue?", default=False):
        console.print("[bold yellow]Registration cancelled.[/]")
        raise typer.Exit(code=0)

    console.print("\n[bold cyan]Registering...[/]")

    try:
        result: RegistrationResult = register_hotkey(
            network=network,
            wallet_name=wallet_name,
            hotkey_name=wallet_hotkey,
            netuid=netuid,
            burned=burned,
            cuda=cuda,
        )
    except bt.KeyFileError as exc:
        _handle_wallet_exception(
            wallet_name=wallet_name, wallet_hotkey=wallet_hotkey, exc=exc
        )
    except typer.Exit:
        raise
    except Exception as exc:
        _handle_unexpected_exception("Registration failed unexpectedly", exc)

    if result.status == "already":
        console.print(f"[bold yellow]Hotkey already registered[/]. UID: {result.uid}")
        return

    if not result.success:
        console.print("[bold red]Registration failed.[/]")
        raise typer.Exit(code=1)

    # Display extrinsic if available
    if result.extrinsic:
        console.print(
            f"[bold green]✔ Your extrinsic has been included as[/] [cyan]{result.extrinsic}[/]"
        )

    # Display balance update if available (already converted to float in register_hotkey)
    if result.balance_before is not None and result.balance_after is not None:
        console.print(
            f"[bold]Balance:[/] {result.balance_before:.4f} τ -> {result.balance_after:.4f} τ"
        )

    # Display success message with UID
    if result.status == "burned":
        console.print(
            "[bold green]✔ Registered on netuid[/] "
            f"[cyan]{netuid}[/] [bold green]with UID[/] [cyan]{result.uid}[/]"
        )
    else:
        console.print(
            "[bold green]✔ Registered on netuid[/] "
            f"[cyan]{netuid}[/] [bold green]with UID[/] [cyan]{result.uid}[/]"
        )

    if result.uid is not None:
        slot_uid = str(result.uid)
        try:
            auth_payload = _build_pair_auth_payload(
                network=network,
                netuid=netuid,
                slot=slot_uid,
                hotkey=result.hotkey,
                wallet_name=wallet_name,
                wallet_hotkey=wallet_hotkey,
                skip_metagraph_check=True,
            )
        except typer.Exit:
            # challenge build failed; already reported.
            return

        try:
            with console.status(
                "[bold cyan]Verifying registration with Cartha verifier[/] (this can take ~30-60 seconds while the network confirms ownership)...",
                spinner="dots",
            ):
                try:
                    password_payload = register_pair_password(
                        hotkey=result.hotkey,
                        slot=slot_uid,
                        network=network,
                        netuid=netuid,
                        message=auth_payload["message"],
                        signature=auth_payload["signature"],
                    )
                except VerifierError as exc:
                    message = str(exc)
                    if exc.status_code == 504 or "timeout" in message.lower():
                        console.print(
                            "[bold yellow]Password generation timed out[/]: run 'cartha pair status' in ~1 minute to check once the verifier completes."
                        )
                    else:
                        console.print(
                            f"[bold yellow]Unable to fetch pair password now[/]: {message}. Run 'cartha pair status' later to confirm."
                        )
                    return
        except typer.Exit:
            raise
        except Exception as exc:
            _handle_unexpected_exception(
                "Verifier password registration failed unexpectedly", exc
            )

        pair_pwd = password_payload.get("pwd")
        if pair_pwd:
            console.print(
                f"[bold green]Pair password[/] for {result.hotkey}/{slot_uid}: [yellow]{pair_pwd}[/]"
            )
            console.print(
                "[bold yellow]Keep it safe[/] — for your eyes only. Exposure might allow others to steal your locked USDC rewards."
            )
        else:
            console.print(
                "[bold yellow]Verifier did not return a pair password[/]. "
                "Run 'cartha pair status' to check availability."
            )
    else:
        console.print(
            "[bold yellow]UID not yet available[/] (node may still be syncing)."
        )


@pair_app.command("status")
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
    """Show the verifier state for a miner pair."""
    try:
        console.print("[bold cyan]Loading wallet...[/]")
        wallet = _load_wallet(wallet_name, wallet_hotkey, None)
        hotkey = wallet.hotkey.ss58_address

        # Fetch UID automatically by default, prompt if disabled
        if slot is None:
            if auto_fetch_uid:
                # Auto-fetch enabled (default) - try to fetch from network
                console.print("[bold cyan]Fetching UID from subnet...[/]")
                try:
                    slot = _get_uid_from_hotkey(
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
        # _ensure_pair_registered(
        #     network=network, netuid=netuid, slot=slot_id, hotkey=hotkey
        # )

        console.print("[bold cyan]Signing hotkey ownership challenge...[/]")
        auth_payload = _build_pair_auth_payload(
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
            status = _request_pair_status_or_password(
                mode="status",
                hotkey=hotkey,
                slot=slot_id,
                network=network,
                netuid=netuid,
                auth_payload=auth_payload,
            )
    except bt.KeyFileError as exc:
        _handle_wallet_exception(
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

        _handle_unexpected_exception("Unable to fetch pair status", exc)

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
            _handle_unexpected_exception(
                "Verifier password generation failed unexpectedly", exc
            )

        console.print("[bold green]Pair password issued.[/]")

        try:
            with console.status(
                "[bold cyan]Refreshing verifier status...[/]",
                spinner="dots",
            ):
                status = _request_pair_status_or_password(
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
    _display_clock_and_countdown()

    table = Table(title="Pair Status", show_header=False)
    table.add_row("Hotkey", hotkey)
    table.add_row("Slot UID", slot_id)
    table.add_row("State", sanitized["state"])

    # Show verified lock amount for verified/active states
    state = sanitized.get("state", "").lower()
    if state in ("verified", "active"):
        verified_amount_usdc = sanitized.get("verified_lock_amount_usdc")
        if verified_amount_usdc is not None:
            # Format amount nicely without scientific notation
            amount_str = f"{verified_amount_usdc:.6f}".rstrip("0").rstrip(".")
            table.add_row("Verified lock amount", f"{amount_str} USDC")

    table.add_row("Password issued", "yes" if sanitized.get("has_pwd") else "no")
    issued_at = sanitized.get("issued_at")
    if issued_at:
        # Try to parse and format the timestamp
        try:
            if isinstance(issued_at, (int, float)) or (
                isinstance(issued_at, str) and issued_at.isdigit()
            ):
                # Numeric timestamp
                formatted_time = _format_timestamp(issued_at)
            elif isinstance(issued_at, str):
                # Try parsing as ISO format datetime string
                try:
                    dt = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                    timestamp = dt.timestamp()
                    formatted_time = _format_timestamp(timestamp)
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
    if password:
        console.print(
            "[bold yellow]Keep it safe[/] — for your eyes only. Exposure might allow others to steal your locked USDC rewards."
        )

    # Explicitly return to ensure clean exit
    return


def _submit_lock_proof_payload(
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
    lock_days: int,
) -> dict[str, Any]:
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
        "lockDays": lock_days,
    }


def _generate_eip712_signature(
    *,
    chain_id: int,
    vault_address: str,
    miner_hotkey: str,
    slot_uid: str,
    tx_hash: str,
    amount: int,
    password: str,
    timestamp: int,
    lock_days: int,
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
        lock_days: Lock period in days (7-365)
        private_key: EVM private key (0x-prefixed hex)

    Returns:
        Tuple of (signature, miner_evm_address)
    """
    if Account is None:
        _exit_with_error(
            "eth-account is required for EIP-712 signing. Install it with: uv sync"
        )

    # Normalize private key
    private_key_normalized = _normalize_hex(private_key)

    # Derive EVM address from private key
    account = Account.from_key(private_key_normalized)
    miner_evm_address = Web3.to_checksum_address(account.address)

    # Normalize password
    password_normalized = _normalize_hex(password)
    if len(password_normalized) != 66:  # 0x + 64 hex chars = 32 bytes
        _exit_with_error("Password must be 32 bytes (0x + 64 hex characters)")

    # Normalize tx hash
    tx_hash_normalized = _normalize_hex(tx_hash.lower())
    if len(tx_hash_normalized) != 66:  # 0x + 64 hex chars = 32 bytes
        _exit_with_error("Transaction hash must be 32 bytes (0x + 64 hex characters)")

    # Build EIP-712 message
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
        lock_days=lock_days,
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


def _send_lock_proof(payload: dict[str, Any], json_output: bool) -> None:
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


@app.command("prove-lock")
def prove_lock(
    payload_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--payload-file",
        help="Path to JSON file generated by build_lock_proof.py. If provided, all other parameters are loaded from this file.",
        show_default=False,
    ),
    chain: int | None = typer.Option(
        None,
        "--chain",
        help="EVM chain ID for the vault transaction.",
        show_default=False,
    ),
    vault: str | None = typer.Option(
        None,
        "--vault",
        help="Vault contract address.",
        show_default=False,
    ),
    tx: str | None = typer.Option(
        None,
        "--tx",
        help="Transaction hash for the LockCreated event.",
        show_default=False,
    ),
    amount: str | None = typer.Option(
        None,
        "--amount",
        help="Lock amount in USDC (e.g. 250.5). Auto-detects if normalized USDC or base units (>1e9). When omitted you'll be prompted.",
        show_default=False,
    ),
    hotkey: str | None = typer.Option(
        None,
        "--hotkey",
        help="Bittensor hotkey SS58 address.",
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
    miner_evm: str | None = typer.Option(
        None,
        "--miner-evm",
        help="EVM address that signed the LockProof payload.",
        show_default=False,
    ),
    password: str | None = typer.Option(
        None,
        "--pwd",
        help="Pair password used when signing the LockProof payload.",
        show_default=False,
    ),
    signature: str | None = typer.Option(
        None,
        "--signature",
        help="Hex EIP-712 signature.",
        show_default=False,
    ),
    timestamp: int | None = typer.Option(
        None,
        "--timestamp",
        help="Unix timestamp (seconds) used when signing the LockProof. Required when using signature from build_lock_proof.py.",
        show_default=False,
    ),
    lock_days: int | None = typer.Option(  # noqa: B008
        None,
        "--lock-days",
        help="Lock period in days (min 7, max 365). Required for lock proof submission.",
        show_default=False,
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit the verifier response as JSON."
    ),
) -> None:
    """Submit a LockProof derived from the given on-chain deposit."""
    try:
        amount_base_units: int | None = None  # Initialize amount_base_units
        # If payload file is provided, load all values from it
        if payload_file is not None:
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
                tx_normalized = _normalize_hex(tx)
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
            if amount is not None and amount != "":
                try:
                    amount_as_int = int(float(amount))
                    if amount_as_int >= 1_000_000_000:  # >= 1e9, likely base units
                        amount_base_units = amount_as_int
                    else:
                        # Treat as normalized USDC
                        amount_base_units = _usdc_to_base_units(amount)
                except (ValueError, InvalidOperation):
                    # If not a valid number, try treating as normalized USDC
                    amount_base_units = _usdc_to_base_units(amount)
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
                password_normalized = _normalize_hex(password)
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
                signature_normalized = _normalize_hex(signature)
                if len(signature_normalized) != 132:
                    console.print(
                        "[bold red]Error:[/] Signature must be 65 bytes (0x + 130 hex characters)"
                    )
                    raise typer.Exit(code=1)
                signature = signature_normalized

            timestamp = (
                timestamp if timestamp is not None else payload_data.get("timestamp")
            )
            lock_days = (
                lock_days
                if lock_days is not None
                else payload_data.get("lock_days") or payload_data.get("lockDays")
            )

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
            if lock_days is None:
                missing_fields.append("lock_days")

            if missing_fields:
                console.print(
                    f"[bold red]Error:[/] Payload file is missing required fields: {', '.join(missing_fields)}\n"
                    f"Make sure the payload file was generated by build_lock_proof.py"
                )
                raise typer.Exit(code=1)

            console.print(f"[dim]Loaded payload from:[/] {payload_file}")

        # Normalize hex fields if provided via CLI args (not from payload file)
        if payload_file is None:
            if signature is not None:
                signature = _normalize_hex(signature)
                if len(signature) != 132:  # 0x + 130 hex chars = 65 bytes
                    console.print(
                        "[bold red]Error:[/] Signature must be 65 bytes (0x + 130 hex characters)"
                    )
                    raise typer.Exit(code=1)
            if password is not None:
                password = _normalize_hex(password)
                if len(password) != 66:  # 0x + 64 hex chars = 32 bytes
                    console.print(
                        "[bold red]Error:[/] Pair password must be 32 bytes (0x + 64 hex characters)"
                    )
                    raise typer.Exit(code=1)
            if tx is not None:
                tx = _normalize_hex(tx)
                if len(tx) != 66:  # 0x + 64 hex chars = 32 bytes
                    console.print(
                        "[bold red]Error:[/] Transaction hash must be 32 bytes (0x + 64 hex characters)"
                    )
                    raise typer.Exit(code=1)
            if miner_evm is not None:
                if not Web3.is_address(miner_evm):
                    console.print(
                        "[bold red]Error:[/] Miner EVM address must be a valid EVM address"
                    )
                    raise typer.Exit(code=1)
                miner_evm = Web3.to_checksum_address(miner_evm)
            if vault is not None:
                if not Web3.is_address(vault):
                    console.print(
                        "[bold red]Error:[/] Vault address must be a valid EVM address"
                    )
                    raise typer.Exit(code=1)
                vault = Web3.to_checksum_address(vault)

        # Ask about signature FIRST, before prompting for other fields
        # This makes the flow more logical: if user has signature, collect it and required fields
        # If not, collect all fields needed to generate signature
        sign_locally: bool | None = (
            None  # Will be set if user needs to generate signature
        )
        _private_key_for_signing: str | None = (
            None  # Store private key if signing locally
        )
        if signature is None:
            has_signature = Confirm.ask(
                "[bold cyan]Do you already have an EIP-712 signature?[/]", default=False
            )

            if has_signature:
                # User has signature from external wallet - collect signature and required fields
                console.print(
                    "\n[bold cyan]Please provide your signature and required fields:[/]"
                )
                while True:
                    signature = typer.prompt(
                        "EIP-712 signature (0x...)", show_default=False
                    )
                    signature_normalized = _normalize_hex(signature)
                    # EIP-712 signature is 65 bytes = 0x + 130 hex chars
                    if len(signature_normalized) == 132:
                        signature = signature_normalized
                        break
                    console.print(
                        "[bold red]Error:[/] Signature must be 65 bytes (0x + 130 hex characters)"
                    )

                if miner_evm is None:
                    while True:
                        miner_evm = typer.prompt(
                            "Miner EVM address", show_default=False
                        )
                        if Web3.is_address(miner_evm):
                            break
                        console.print(
                            "[bold red]Error:[/] Miner EVM address must be a valid EVM address (0x...)"
                        )

                # Ask for timestamp if not provided (required for signature verification)
                # The timestamp must match the one used when creating the signature
                if timestamp is None:
                    console.print(
                        "[yellow]Note:[/] The timestamp must match the one used when creating the signature."
                    )
                    while True:
                        try:
                            timestamp_input = typer.prompt(
                                "Timestamp used when signing (Unix timestamp in seconds)",
                                show_default=False,
                            )
                            timestamp = int(timestamp_input)
                            if timestamp <= 0:
                                console.print(
                                    "[bold red]Error:[/] Timestamp must be a positive integer"
                                )
                                continue
                            break
                        except ValueError:
                            console.print(
                                "[bold red]Error:[/] Timestamp must be a valid integer"
                            )
            else:
                # Need to generate signature - get private key first if signing locally
                sign_locally = Confirm.ask(
                    "[bold cyan]Sign locally with private key?[/]", default=True
                )

                if sign_locally:
                    # Get private key immediately and derive EVM address
                    console.print(
                        "\n[bold cyan]Please provide your EVM private key:[/]"
                    )
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
                        # Get private key (from env or prompt)
                        private_key = (
                            private_key_from_env
                            if private_key_from_env
                            else typer.prompt(
                                "EVM private key (0x...)",
                                hide_input=True,
                                show_default=False,
                            )
                        )

                        # Normalize and validate private key
                        try:
                            private_key_normalized = _normalize_hex(private_key)
                            if (
                                len(private_key_normalized) != 66
                            ):  # 0x + 64 hex chars = 32 bytes
                                console.print(
                                    "[bold red]Error:[/] Private key must be 32 bytes (0x + 64 hex characters)"
                                )
                                # If using env var, clear it so we re-prompt
                                if private_key_from_env:
                                    private_key_from_env = None
                                continue

                            # Derive EVM address from private key
                            if Account is None:
                                _exit_with_error(
                                    "eth-account is required for EIP-712 signing. Install it with: uv sync"
                                )
                            account = Account.from_key(private_key_normalized)
                            derived_evm = Web3.to_checksum_address(account.address)

                            # Show derived address and confirm
                            console.print(
                                f"\n[bold cyan]Derived EVM address:[/] {derived_evm}"
                            )
                            if miner_evm is not None:
                                if miner_evm.lower() != derived_evm.lower():
                                    console.print(
                                        f"[yellow]Warning:[/] Provided EVM address ({miner_evm}) "
                                        f"does not match private key address ({derived_evm})"
                                    )
                                    if not typer.confirm(
                                        "Continue anyway?", default=False
                                    ):
                                        # If using env var, clear it so we re-prompt
                                        if private_key_from_env:
                                            private_key_from_env = None
                                        continue
                                else:
                                    console.print(
                                        "[bold green]✓ EVM address matches[/]"
                                    )
                            else:
                                # Confirm the derived address is correct
                                if not Confirm.ask(
                                    "[bold cyan]Is this your correct EVM address?[/]",
                                    default=True,
                                ):
                                    console.print(
                                        "[bold yellow]Please use a different private key.[/]"
                                    )
                                    # If using env var, clear it so we re-prompt
                                    if private_key_from_env:
                                        private_key_from_env = None
                                    continue
                                miner_evm = derived_evm
                                console.print("[bold green]✓ EVM address confirmed[/]")

                            # Success - store private key for later signature generation
                            _private_key_for_signing = private_key_normalized
                            break
                        except Exception as exc:
                            console.print(
                                f"[bold red]Error:[/] Failed to derive EVM address: {exc}"
                            )
                            # If using env var, clear it so we re-prompt
                            if private_key_from_env:
                                private_key_from_env = None
                            continue
                else:
                    console.print(
                        "\n[bold cyan]You'll need to sign externally. "
                        "We'll collect all fields first, then show you the message to sign.[/]"
                    )
                    _private_key_for_signing = None

        # Now prompt for all required fields (needed for both signature generation and submission)
        # Validate each field immediately after input
        if chain is None:
            while True:
                try:
                    chain_input = typer.prompt("\nChain ID", show_default=False)
                    chain = int(chain_input)
                    if chain <= 0:
                        console.print(
                            "[bold red]Error:[/] Chain ID must be a positive integer"
                        )
                        continue
                    break
                except ValueError:
                    console.print(
                        "[bold red]Error:[/] Chain ID must be a valid integer"
                    )

        if vault is None:
            while True:
                vault = typer.prompt("Vault contract address", show_default=False)
                if Web3.is_address(vault):
                    break
                console.print(
                    "[bold red]Error:[/] Vault address must be a valid EVM address (0x...)"
                )

        if tx is None:
            while True:
                tx = typer.prompt("Transaction hash", show_default=False)
                tx_normalized = _normalize_hex(tx)
                if len(tx_normalized) == 66:  # 0x + 64 hex chars = 32 bytes
                    tx = tx_normalized
                    break
                console.print(
                    "[bold red]Error:[/] Transaction hash must be 32 bytes (0x + 64 hex characters)"
                )

        if amount is None:
            while True:
                try:
                    normalized_input = typer.prompt(
                        "Lock amount in USDC (e.g. 250.5)", show_default=False
                    )
                    amount_base_units = _usdc_to_base_units(normalized_input)
                    if amount_base_units <= 0:
                        console.print("[bold red]Error:[/] Amount must be positive")
                        continue
                    break
                except Exception as exc:
                    console.print(f"[bold red]Error:[/] Invalid amount: {exc}")
        else:
            # Only convert if amount_base_units is not already set (e.g., from payload file)
            if amount_base_units is None:
                # Auto-detect: if amount as int would be >= 1e9, assume base units
                # Otherwise, treat as normalized USDC
                try:
                    amount_as_int = int(float(amount))
                    if amount_as_int >= 1_000_000_000:  # >= 1e9, likely base units
                        amount_base_units = amount_as_int
                    else:
                        # Treat as normalized USDC
                        amount_base_units = _usdc_to_base_units(amount)
                except (ValueError, InvalidOperation):
                    # If not a valid number, try treating as normalized USDC
                    amount_base_units = _usdc_to_base_units(amount)

        if hotkey is None:
            while True:
                hotkey = typer.prompt("Hotkey SS58 address", show_default=False)
                if hotkey.startswith("bt1") or hotkey.startswith("5"):
                    if len(hotkey) >= 10:  # Basic SS58 format check
                        break
                console.print(
                    "[bold red]Error:[/] Hotkey must be a valid SS58 address (starts with 'bt1' or '5')"
                )

        if slot is None:
            # Fetch UID automatically by default, prompt if disabled
            if auto_fetch_uid:
                # Auto-fetch enabled (default) - try to fetch from network
                if hotkey is None:
                    console.print(
                        "[bold red]Error:[/] Cannot fetch UID: hotkey must be provided first."
                    )
                    raise typer.Exit(code=1)

                console.print("[bold cyan]Fetching UID from subnet...[/]")
                try:
                    slot = _get_uid_from_hotkey(
                        network=settings.network, netuid=settings.netuid, hotkey=hotkey
                    )
                    if slot is None:
                        console.print(
                            "[bold yellow]Hotkey is not registered or has been deregistered[/] "
                            f"on netuid {settings.netuid} ({settings.network} network)."
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

        if password is None:
            while True:
                password = typer.prompt(
                    "Pair password (0x...)", hide_input=True, show_default=False
                )
                password_normalized = _normalize_hex(password)
                if len(password_normalized) == 66:  # 0x + 64 hex chars = 32 bytes
                    password = password_normalized
                    break
                console.print(
                    "[bold red]Error:[/] Pair password must be 32 bytes (0x + 64 hex characters)"
                )

        if lock_days is None:
            while True:
                try:
                    lock_days_input = typer.prompt(
                        "Lock period in days (min 7, max 365)",
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

        # Generate signature if needed (user said they don't have one)
        if signature is None:
            # sign_locally and _private_key_for_signing were determined above
            if sign_locally and _private_key_for_signing:
                # Generate timestamp if not provided
                if timestamp is None:
                    timestamp = int(time.time())

                # Generate signature using the private key we already collected
                console.print("\n[dim]Generating EIP-712 signature...[/]")
                try:
                    signature, derived_evm_str = _generate_eip712_signature(
                        chain_id=chain,
                        vault_address=vault,
                        miner_hotkey=hotkey,
                        slot_uid=str(slot),
                        tx_hash=tx,
                        amount=amount_base_units,
                        password=password,
                        timestamp=timestamp,
                        lock_days=lock_days,
                        private_key=_private_key_for_signing,
                    )
                    # Convert to ChecksumAddress for comparison
                    derived_evm = Web3.to_checksum_address(derived_evm_str)
                    # Verify the address still matches (should always match since we confirmed it earlier)
                    if (
                        miner_evm is not None
                        and miner_evm.lower() != derived_evm.lower()
                    ):
                        console.print(
                            f"[yellow]Warning:[/] EVM address mismatch detected. "
                            f"Expected {miner_evm}, got {derived_evm}"
                        )
                        if not typer.confirm("Continue anyway?", default=False):
                            raise typer.Exit(code=1)
                    console.print("[bold green]✓ Signature generated[/]")
                except Exception as exc:
                    _handle_unexpected_exception("Failed to generate signature", exc)
            else:
                # External signing (MetaMask, etc.)
                # Ensure timestamp is set
                if timestamp is None:
                    timestamp = int(time.time())

                # Ensure miner_evm is set (needed for EIP-712 message)
                if miner_evm is None:
                    while True:
                        miner_evm = typer.prompt(
                            "Miner EVM address (the address that will sign)",
                            show_default=False,
                        )
                        if Web3.is_address(miner_evm):
                            miner_evm = Web3.to_checksum_address(miner_evm)
                            break
                        console.print(
                            "[bold red]Error:[/] Miner EVM address must be a valid EVM address (0x...)"
                        )

                # Build EIP-712 message structure
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
                    lock_days=lock_days,
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
                # Use the already-serialized JSON string to preserve exact formatting
                with open(json_filename, "w") as f:
                    f.write(json_str)

                # Create human-readable instructions file
                human_amount = Decimal(amount_base_units) / Decimal(10**6)
                amount_str = f"{human_amount:.6f}".rstrip("0").rstrip(".")

                instructions = f"""EIP-712 LockProof Signing Instructions
Generated: {datetime.now(UTC).isoformat()}

IMPORTANT: Copy the JSON from {json_filename.name} exactly as-is. Do not modify any values, spacing, or formatting.

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

                console.print("\n[bold green]✓ EIP-712 message files generated[/]")
                console.print(f"[bold cyan]JSON file:[/] {json_filename}")
                console.print(f"[bold cyan]Instructions:[/] {txt_filename}")
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
                    signature_normalized = _normalize_hex(signature)
                    # EIP-712 signature is 65 bytes = 0x + 130 hex chars
                    if len(signature_normalized) == 132:
                        signature = signature_normalized
                        break
                    console.print(
                        "[bold red]Error:[/] Signature must be 65 bytes (0x + 130 hex characters)"
                    )

        # Ensure miner_evm is set if signature was provided but miner_evm wasn't
        if miner_evm is None:
            while True:
                miner_evm = typer.prompt("Miner EVM address", show_default=False)
                if Web3.is_address(miner_evm):
                    break
                console.print(
                    "[bold red]Error:[/] Miner EVM address must be a valid EVM address (0x...)"
                )

        # Ensure timestamp is set (required for signature verification)
        if timestamp is None:
            timestamp = int(time.time())

        # Ensure all required fields are set (mypy type narrowing)
        # Note: amount_base_units is guaranteed to be set by the logic above
        assert amount_base_units is not None, "Amount must be set"
        assert chain is not None, "Chain ID must be set"
        assert vault is not None, "Vault address must be set"
        assert tx is not None, "Transaction hash must be set"
        assert hotkey is not None, "Hotkey must be set"
        assert slot is not None, "Slot UID must be set"
        assert miner_evm is not None, "Miner EVM address must be set"
        assert password is not None, "Pair password must be set"
        assert signature is not None, "Signature must be set"
        assert timestamp is not None, "Timestamp must be set"
        assert lock_days is not None, "Lock days must be set"

        slot_id = str(slot)
        payload = _submit_lock_proof_payload(
            chain=chain,
            vault=vault,
            tx_hash=tx,
            amount=amount_base_units,
            hotkey=hotkey,
            slot=slot_id,
            miner_evm=miner_evm,
            password=password,
            signature=signature,
            timestamp=timestamp,
            lock_days=lock_days,
        )

        # Show summary and confirm before submission
        if not json_output:
            human_amount = Decimal(payload["amount"]) / Decimal(10**6)
            amount_str = f"{human_amount:.6f}".rstrip("0").rstrip(".")
            console.print("\n[bold cyan]Lock Proof Summary:[/]")
            summary_table = Table(show_header=False, box=box.SIMPLE)
            summary_table.add_column(style="cyan")
            summary_table.add_column(style="yellow")
            summary_table.add_row("Chain ID", str(chain))
            summary_table.add_row("Vault", vault)
            summary_table.add_row("Transaction", tx)
            summary_table.add_row(
                "Amount", f"{amount_str} USDC ({payload['amount']} base units)"
            )
            summary_table.add_row("Hotkey", hotkey)
            summary_table.add_row("Slot UID", slot_id)
            summary_table.add_row("EVM Address", miner_evm)
            summary_table.add_row("Lock Days", str(lock_days))
            summary_table.add_row(
                "Signature",
                payload["signature"][:20] + "..." + payload["signature"][-10:],
            )
            console.print(summary_table)
            console.print()

            # Display clock and countdown
            _display_clock_and_countdown()
        else:
            # In JSON mode, show a simple summary before confirmation
            console.print(
                f"[dim]Preparing to submit lock proof: "
                f"chain={chain}, vault={vault}, amount={payload['amount']}, "
                f"hotkey={hotkey}, slot={slot_id}[/]"
            )

        # Use Rich Confirm for styled prompt
        if not Confirm.ask(
            "[bold yellow]Submit this lock proof to the verifier?[/]", default=True
        ):
            if json_output:
                # In JSON mode, output cancellation as JSON
                console.print(json.dumps({"ok": False, "cancelled": True}))
            else:
                console.print("[bold yellow]Submission cancelled.[/]")
            raise typer.Exit(code=0)

        _send_lock_proof(payload, json_output)
        if not json_output:
            human_amount = Decimal(payload["amount"]) / Decimal(10**6)
            # Format amount nicely without scientific notation
            amount_str = f"{human_amount:.6f}".rstrip("0").rstrip(".")
            console.print("\n[bold green]✓ Lock proof submitted successfully[/]")
            console.print(
                f"[bold cyan]Amount submitted[/]: {amount_str} USDC "
                f"({payload['amount']} base units)"
            )
            console.print(
                "[bold cyan]Reminder[/]: keep your pair password private to prevent USDC theft."
            )
    except typer.Exit:
        raise
    except Exception as exc:
        _handle_unexpected_exception("Lock proof submission failed", exc)


@app.command("claim-deposit")
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
        chain=chain,
        vault=vault,
        tx=tx,
        amount=amount_str,
        hotkey=hotkey,
        slot=slot,
        miner_evm=miner_evm,
        password=password,
        signature=signature,
        timestamp=timestamp,
        json_output=json_output,
    )


if __name__ == "__main__":  # pragma: no cover
    app()
