"""Primary Typer application for the Cartha CLI."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

import bittensor as bt
import typer
from web3 import Web3

from .bt import RegistrationResult, get_subtensor, get_wallet, register_hotkey
from .config import settings
from .verifier import (
    VerifierError,
    fetch_pair_password,
    fetch_pair_status,
    submit_lock_proof,
)

CHALLENGE_PREFIX = "cartha-pair-auth"
CHALLENGE_TTL_SECONDS = 120


app = typer.Typer(help="Command line tooling for Cartha subnet miners.")
subnet_app = typer.Typer(help="Subnet management commands.")
pair_app = typer.Typer(help="Pair status commands.")


app.add_typer(subnet_app, name="s")
app.add_typer(pair_app, name="pair")


@app.callback()
def cli_root() -> None:
    """Top-level callback to ensure settings load on startup."""
    if settings.verifier_url.startswith("http://127.0.0.1"):
        typer.echo(f"Using local verifier endpoint: {settings.verifier_url}")
    else:
        typer.echo("Using configured verifier endpoint: Cartha")


@app.command()
def version() -> None:
    """Print the CLI version."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        typer.echo(version("cartha-cli"))
    except PackageNotFoundError:  # pragma: no cover
        typer.echo("0.0.0")


def _ensure_pair_registered(
    *,
    network: str,
    netuid: int,
    slot: str,
    hotkey: str,
) -> None:
    subtensor = get_subtensor(network)
    metagraph = subtensor.metagraph(netuid)
    slot_index = int(slot)
    if slot_index < 0 or slot_index >= len(metagraph.hotkeys):
        typer.secho(
            f"UID {slot} not found in the metagraph (netuid {netuid}).",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)
    registered_hotkey = metagraph.hotkeys[slot_index]
    if registered_hotkey != hotkey:
        typer.secho(
            f"UID {slot} belongs to hotkey {registered_hotkey}, not {hotkey}.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)


def _load_wallet(wallet_name: str, wallet_hotkey: str, expected_hotkey: str) -> bt.wallet:
    try:
        wallet = get_wallet(wallet_name, wallet_hotkey)
    except bt.KeyFileError as exc:
        typer.secho(
            f"Hotkey files for wallet '{wallet_name}/{wallet_hotkey}' are missing. "
            "Import or create the wallet before retrying.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # pragma: no cover - defensive
        typer.secho(f"Failed to load wallet: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    if wallet.hotkey.ss58_address != expected_hotkey:
        typer.secho(
            "Loaded wallet hotkey does not match the supplied hotkey address.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    if not getattr(wallet.hotkey, "is_unlocked", lambda: False)():
        typer.secho(
            "Hotkey is locked. Run "
            "`btcli wallet unlock --wallet.name ... --wallet.hotkey ...` "
            "and try again.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    return wallet


def _build_pair_auth_payload(
    *,
    network: str,
    netuid: int,
    slot: str,
    hotkey: str,
    wallet_name: str,
    wallet_hotkey: str,
) -> dict[str, Any]:
    _ensure_pair_registered(network=network, netuid=netuid, slot=slot, hotkey=hotkey)

    wallet = _load_wallet(wallet_name, wallet_hotkey, hotkey)

    timestamp = int(time.time())
    message = (
        f"{CHALLENGE_PREFIX}|network:{network}|netuid:{netuid}|slot:{slot}|"
        f"hotkey:{hotkey}|ts:{timestamp}"
    )
    message_bytes = message.encode("utf-8")
    signature_bytes = wallet.hotkey.sign(message_bytes)

    verifier_keypair = bt.Keypair(ss58_address=hotkey)
    if not verifier_keypair.verify(message_bytes, signature_bytes):
        typer.secho("Unable to verify the ownership signature locally.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    expires_at = timestamp + CHALLENGE_TTL_SECONDS
    expiry_time = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()
    typer.echo(
        f"Ownership challenge signed (expires {CHALLENGE_TTL_SECONDS}s from now at {expiry_time})."
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
        typer.secho(f"Verifier request failed: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    raise RuntimeError(f"Unknown mode {mode}")  # pragma: no cover


@subnet_app.command("register")
def subnet_register(
    network: str = typer.Option(settings.network, "--network", help="Bittensor network name."),
    wallet_name: str = typer.Option(
        ..., "--wallet-name", "--wallet.name", help="Coldkey wallet name."
    ),
    wallet_hotkey: str = typer.Option(
        ..., "--wallet-hotkey", "--wallet.hotkey", help="Hotkey name."
    ),
    netuid: int = typer.Option(settings.netuid, "--netuid", help="Subnet netuid."),
    burned: bool = typer.Option(
        True,
        "--burned/--pow",
        help="Burned registration by default; pass --pow to run PoW registration.",
    ),
    cuda: bool = typer.Option(False, "--cuda", help="Enable CUDA for PoW registration."),
) -> None:
    """Register the specified hotkey on the target subnet and print the UID."""

    typer.echo(f"Registering hotkey '{wallet_hotkey}' on netuid {netuid} (network={network})")

    result: RegistrationResult = register_hotkey(
        network=network,
        wallet_name=wallet_name,
        hotkey_name=wallet_hotkey,
        netuid=netuid,
        burned=burned,
        cuda=cuda,
    )

    if result.status == "already":
        typer.echo(f"Hotkey already registered. UID: {result.uid}")
        return

    if not result.success:
        typer.secho("Registration failed.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if result.status == "burned":
        typer.echo("Burned registration success.")
    else:
        typer.echo("Registration success.")

    if result.uid is not None:
        slot_uid = str(result.uid)
        typer.echo(f"Registered uid: {slot_uid}")
        auth_payload = _build_pair_auth_payload(
            network=network,
            netuid=netuid,
            slot=slot_uid,
            hotkey=result.hotkey,
            wallet_name=wallet_name,
            wallet_hotkey=wallet_hotkey,
        )
        password_payload = _request_pair_status_or_password(
            mode="password",
            hotkey=result.hotkey,
            slot=slot_uid,
            network=network,
            netuid=netuid,
            auth_payload=auth_payload,
        )
        pair_pwd = password_payload.get("pwd")
        if pair_pwd:
            typer.secho(
                f"Pair password for {result.hotkey}/{slot_uid}: {pair_pwd}",
                fg=typer.colors.GREEN,
            )
            typer.secho(
                "Keep it safe—eyes only. Exposure lets others steal your locked USDC deposit.",
                fg=typer.colors.YELLOW,
            )
        else:
            typer.secho(
                "Verifier did not return a pair password. "
                "Run 'cartha pair status' to check availability.",
                fg=typer.colors.YELLOW,
            )
    else:
        typer.echo("Warning: UID not yet available (node may still be syncing).")


@pair_app.command("status")
def pair_status(
    hotkey: str = typer.Option(..., "--hotkey", help="Bittensor hotkey SS58 address."),
    slot: int = typer.Option(..., "--slot", help="Subnet UID assigned to the miner."),
    wallet_name: str = typer.Option(
        ..., "--wallet-name", "--wallet.name", help="Coldkey wallet name for signing."
    ),
    wallet_hotkey: str = typer.Option(
        ..., "--wallet-hotkey", "--wallet.hotkey", help="Hotkey name used for signing."
    ),
    network: str = typer.Option(settings.network, "--network", help="Bittensor network name."),
    netuid: int = typer.Option(settings.netuid, "--netuid", help="Subnet netuid."),
    json_output: bool = typer.Option(False, "--json", help="Emit the raw JSON response."),
) -> None:
    """Show the verifier state for a miner pair."""
    slot_id = str(slot)
    auth_payload = _build_pair_auth_payload(
        network=network,
        netuid=netuid,
        slot=slot_id,
        hotkey=hotkey,
        wallet_name=wallet_name,
        wallet_hotkey=wallet_hotkey,
    )
    status = _request_pair_status_or_password(
        mode="status",
        hotkey=hotkey,
        slot=slot_id,
        network=network,
        netuid=netuid,
        auth_payload=auth_payload,
    )

    sanitized = {k: v for k, v in status.items() if k != "pwd"}
    sanitized.setdefault("state", "unknown")
    sanitized["hotkey"] = hotkey
    sanitized["slot"] = slot_id

    if json_output:
        typer.echo(json.dumps(sanitized, indent=2))
        return

    typer.echo(f"Hotkey: {hotkey}")
    typer.echo(f"Slot UID: {slot_id}")
    typer.echo(f"State: {sanitized['state']}")
    typer.echo(f"Password issued: {'yes' if sanitized.get('has_pwd') else 'no'}")
    issued_at = sanitized.get("issued_at")
    if issued_at:
        typer.echo(f"Password issued at: {issued_at}")


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
        typer.secho("Amount must be a positive integer.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if not Web3.is_address(vault):
        typer.secho("Vault address must be a valid EVM address.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    if not Web3.is_address(miner_evm):
        typer.secho("Miner EVM address must be a valid address.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if not tx_hash.startswith("0x"):
        typer.secho("Transaction hash must be a 0x-prefixed hex string.", fg=typer.colors.RED)
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
        typer.secho(f"Lock proof rejected: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if json_output:
        typer.echo(json.dumps(response, indent=2))
    else:
        typer.echo("Lock proof submitted successfully.")


@app.command("prove-lock")
def prove_lock(
    chain: int = typer.Option(..., "--chain", help="EVM chain ID for the vault transaction."),
    vault: str = typer.Option(..., "--vault", help="Vault contract address."),
    tx: str = typer.Option(..., "--tx", help="Transaction hash for the LockCreated event."),
    amount: int = typer.Option(..., "--amount", help="Lock amount in wei."),
    hotkey: str = typer.Option(..., "--hotkey", help="Bittensor hotkey SS58 address."),
    slot: int = typer.Option(..., "--slot", help="Subnet UID assigned to the miner."),
    miner_evm: str = typer.Option(
        ..., "--miner-evm", help="EVM address that signed the LockProof payload."
    ),
    password: str = typer.Option(
        ..., "--pwd", help="Pair password used when signing the LockProof payload."
    ),
    signature: str = typer.Option(..., "--signature", help="Hex EIP-712 signature."),
    json_output: bool = typer.Option(False, "--json", help="Emit the verifier response as JSON."),
) -> None:
    """Submit a LockProof derived from the given on-chain deposit."""
    slot_id = str(slot)
    payload = _submit_lock_proof_payload(
        chain=chain,
        vault=vault,
        tx_hash=tx,
        amount=amount,
        hotkey=hotkey,
        slot=slot_id,
        miner_evm=miner_evm,
        password=password,
        signature=signature,
    )
    _send_lock_proof(payload, json_output)


@app.command("claim-deposit")
def claim_deposit(
    chain: int = typer.Option(..., "--chain", help="EVM chain ID for the vault transaction."),
    vault: str = typer.Option(..., "--vault", help="Vault contract address."),
    tx: str = typer.Option(..., "--tx", help="Transaction hash for the LockCreated event."),
    amount: int = typer.Option(..., "--amount", help="Lock amount in wei."),
    hotkey: str = typer.Option(..., "--hotkey", help="Bittensor hotkey SS58 address."),
    slot: int = typer.Option(..., "--slot", help="Subnet UID assigned to the miner."),
    miner_evm: str = typer.Option(
        ..., "--miner-evm", help="EVM address that signed the LockProof payload."
    ),
    password: str = typer.Option(
        ..., "--pwd", help="Pair password used when signing the LockProof payload."
    ),
    signature: str = typer.Option(..., "--signature", help="Hex EIP-712 signature."),
    json_output: bool = typer.Option(False, "--json", help="Emit the verifier response as JSON."),
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
