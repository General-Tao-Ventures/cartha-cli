"""Primary Typer application for the Cartha CLI."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from typing import Any

import bittensor as bt
import typer
from rich import box
from rich.console import Console
from rich.json import JSON
from rich.rule import Rule
from rich.table import Table
from web3 import Web3

from .bt import (
    RegistrationResult,
    get_burn_cost,
    get_subtensor,
    get_wallet,
    register_hotkey,
)
from .config import settings
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


def _exit_with_error(message: str, code: int = 1) -> None:
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

    env_table = Table(
        title="Environment", box=box.SQUARE_DOUBLE_HEAD, show_header=False
    )
    env_table.add_row(
        "CARTHA_VERIFIER_URL", "Verifier endpoint (default http://127.0.0.1:8000)"
    )
    env_table.add_row(
        "CARTHA_NETWORK / CARTHA_NETUID", "Default network + subnet (finney / 35)."
    )
    env_table.add_row(
        "BITTENSOR_WALLET_PATH",
        "Override wallet path if keys are not in the default location.",
    )
    console.print(env_table)
    console.print()
    console.print("[dim]Made with ❤ by GTV[/]")


def _log_endpoint_banner() -> None:
    if settings.verifier_url.startswith("http://127.0.0.1"):
        console.print("[bold cyan]Using local verifier endpoint[/]")
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


def _ensure_pair_registered(
    *,
    network: str,
    netuid: int,
    slot: str,
    hotkey: str,
) -> None:
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
            raise typer.Exit(code=1)
        # Re-raise other exceptions as-is
        raise


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
    expiry_time = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()
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
        console.print(f"[bold red]Verifier request failed[/]: {exc}")
        raise typer.Exit(code=1)
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
    slot: int = typer.Option(
        ...,
        "--slot",
        prompt="Slot UID",
        help="Subnet UID assigned to the miner.",
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
    """Show the verifier state for a miner pair."""
    try:
        console.print("[bold cyan]Validating miner UID:hotkey ownership...[/]")
        wallet = _load_wallet(wallet_name, wallet_hotkey, None)
        hotkey = wallet.hotkey.ss58_address
        slot_id = str(slot)
        _ensure_pair_registered(
            network=network, netuid=netuid, slot=slot_id, hotkey=hotkey
        )

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
    except Exception as exc:
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
            raise typer.Exit(code=1)
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

    table = Table(title="Pair Status", show_header=False)
    table.add_row("Hotkey", hotkey)
    table.add_row("Slot UID", slot_id)
    table.add_row("State", sanitized["state"])

    # Show verified lock amount for verified/active states
    state = sanitized.get("state", "").lower()
    if state in ("verified", "active"):
        verified_amount_usdc = sanitized.get("verified_lock_amount_usdc")
        verified_amount_base = sanitized.get("verified_lock_amount_base_units")
        if verified_amount_usdc is not None:
            # Format amount nicely without scientific notation
            amount_str = f"{verified_amount_usdc:.6f}".rstrip("0").rstrip(".")
            table.add_row("Verified lock amount", f"{amount_str} USDC")

    table.add_row("Password issued", "yes" if sanitized.get("has_pwd") else "no")
    issued_at = sanitized.get("issued_at")
    if issued_at:
        table.add_row("Password issued at", issued_at)
    if password:
        table.add_row("Pair password", password)
    console.print(table)
    if password:
        console.print(
            "[bold yellow]Keep it safe[/] — for your eyes only. Exposure might allow others to steal your locked USDC rewards."
        )


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

    return {
        "vaultAddress": Web3.to_checksum_address(vault),
        "minerEvmAddress": Web3.to_checksum_address(miner_evm),
        "minerHotkey": hotkey,
        "slotUID": slot,
        "chainId": chain,
        "txHash": tx_hash.lower(),
        "amount": amount,
        "pwd": password,
        "signature": signature,
    }


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
        raise typer.Exit(code=1)

    if json_output:
        console.print(JSON.from_data(response))
    else:
        console.print("[bold green]Lock proof submitted successfully.[/]")


@app.command("prove-lock")
def prove_lock(
    chain: int | None = typer.Option(
        None,
        "--chain",
        help="EVM chain ID for the vault transaction.",
        prompt="Chain ID",
        show_default=False,
    ),
    vault: str | None = typer.Option(
        None,
        "--vault",
        help="Vault contract address.",
        prompt="Vault contract address",
        show_default=False,
    ),
    tx: str | None = typer.Option(
        None,
        "--tx",
        help="Transaction hash for the LockCreated event.",
        prompt="Transaction hash",
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
        prompt="Hotkey SS58 address",
        show_default=False,
    ),
    slot: int | None = typer.Option(
        None,
        "--slot",
        help="Subnet UID assigned to the miner.",
        prompt="Slot UID",
        show_default=False,
    ),
    miner_evm: str | None = typer.Option(
        None,
        "--miner-evm",
        help="EVM address that signed the LockProof payload.",
        prompt="Miner EVM address",
        show_default=False,
    ),
    password: str | None = typer.Option(
        None,
        "--pwd",
        help="Pair password used when signing the LockProof payload.",
        prompt="Pair password (0x...)",
        show_default=False,
    ),
    signature: str | None = typer.Option(
        None,
        "--signature",
        help="Hex EIP-712 signature.",
        prompt="EIP-712 signature (0x...)",
        show_default=False,
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit the verifier response as JSON."
    ),
) -> None:
    """Submit a LockProof derived from the given on-chain deposit."""
    try:
        if chain is None:
            chain = int(typer.prompt("Chain ID"))
        if vault is None:
            vault = typer.prompt("Vault contract address")
        if tx is None:
            tx = typer.prompt("Transaction hash")
        if amount is None:
            normalized_input = typer.prompt(
                "Lock amount in USDC (e.g. 250.5)", default="250"
            )
            amount_base_units = _usdc_to_base_units(normalized_input)
        else:
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
            hotkey = typer.prompt("Hotkey SS58 address")
        if slot is None:
            slot = int(typer.prompt("Slot UID"))
        if miner_evm is None:
            miner_evm = typer.prompt("Miner EVM address")
        if password is None:
            password = typer.prompt("Pair password (0x...)", hide_input=False)
        if signature is None:
            signature = typer.prompt("EIP-712 signature (0x...)")

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
        )
        _send_lock_proof(payload, json_output)
        if not json_output:
            human_amount = Decimal(payload["amount"]) / Decimal(10**6)
            # Format amount nicely without scientific notation
            amount_str = f"{human_amount:.6f}".rstrip("0").rstrip(".")
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
        None, "--pwd", prompt="Pair password (0x...)", show_default=False
    ),
    signature: str | None = typer.Option(
        None, "--signature", prompt="EIP-712 signature (0x...)", show_default=False
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit the verifier response as JSON."
    ),
) -> None:
    """Alias for prove-lock for deposit-first workflows."""
    prove_lock(
        chain=chain,
        vault=vault,
        tx=tx,
        amount=amount,
        hotkey=hotkey,
        slot=slot,
        miner_evm=miner_evm,
        password=password,
        signature=signature,
        json_output=json_output,
    )


if __name__ == "__main__":  # pragma: no cover
    app()
