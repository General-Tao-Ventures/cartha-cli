"""Primary Typer application for the Cartha CLI."""

from __future__ import annotations

import json

import typer
from eth_account import Account
from web3 import Web3

from .bt import RegistrationResult, register_hotkey
from .config import settings
from .eth712 import LockProofMessage
from .verifier import (
    VerifierError,
    fetch_pair_password,
    fetch_pair_status,
    submit_lock_proof,
)

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


def _load_evm_account() -> Account:
    """Return the local account from configuration or an interactive prompt."""
    private_key = settings.evm_private_key
    if not private_key:
        private_key = typer.prompt("Enter EVM private key", hide_input=True)
    private_key = private_key.strip()
    if not private_key:
        typer.secho("EVM private key required.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    try:
        return Account.from_key(private_key)
    except (TypeError, ValueError) as exc:
        typer.secho(f"Invalid EVM private key: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)


def _submit_lock_proof(
    *,
    chain: int,
    vault: str,
    tx_hash: str,
    amount: int,
    hotkey: str,
    slot: str,
    json_output: bool,
) -> None:
    if amount <= 0:
        typer.secho("Amount must be a positive integer.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if not Web3.is_address(vault):
        typer.secho("Vault address must be a valid EVM address.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    checksum_vault = Web3.to_checksum_address(vault)

    if not tx_hash.startswith("0x"):
        try:
            tx_hash = Web3.to_hex(hexstr=tx_hash)
        except ValueError:
            typer.secho("Transaction hash must be a valid hex string.", fg=typer.colors.RED)
            raise typer.Exit(code=1)
    tx_hash = tx_hash.lower()

    account = _load_evm_account()
    miner_evm_address = Web3.to_checksum_address(account.address)

    try:
        status = fetch_pair_status(hotkey, slot)
    except VerifierError as exc:
        typer.secho(f"Failed to fetch pair status: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    state = status.get("state", "unknown")
    if state in {"revoked", "unknown"}:
        typer.secho(f"Pair state is '{state}'. Cannot submit lock proof.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    if not status.get("has_pwd"):
        typer.secho("Verifier reports that no pair password has been issued yet.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    try:
        password_payload = fetch_pair_password(hotkey, slot)
    except VerifierError as exc:
        typer.secho(f"Failed to fetch pair password: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    password = password_payload.get("pwd")
    if not password:
        typer.secho("Verifier did not return a pair password.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    message = LockProofMessage(
        chain_id=chain,
        vault_address=checksum_vault,
        miner_evm_address=miner_evm_address,
        miner_hotkey=hotkey,
        slot_uid=slot,
        tx_hash=tx_hash,
        amount=amount,
        password=password,
    )
    try:
        encoded = message.encode()
    except ValueError as exc:
        typer.secho(f"Unable to encode LockProof payload: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    signed = account.sign_message(encoded)

    payload = {
        "vaultAddress": checksum_vault,
        "minerEvmAddress": miner_evm_address,
        "minerHotkey": hotkey,
        "slotUID": slot,
        "chainId": chain,
        "txHash": tx_hash,
        "amount": amount,
        "pwd": password,
        "signature": signed.signature.hex(),
    }

    try:
        response = submit_lock_proof(payload)
    except VerifierError as exc:
        typer.secho(f"Lock proof rejected: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    if json_output:
        typer.echo(json.dumps(response, indent=2))
    else:
        typer.echo("Lock proof submitted successfully.")


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
        try:
            password_payload = fetch_pair_password(result.hotkey, slot_uid)
        except VerifierError as exc:
            typer.secho(f"Unable to fetch pair password: {exc}", fg=typer.colors.YELLOW)
        else:
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
                    "Verifier did not return a pair password. Run 'cartha pair status' to check availability.",
                    fg=typer.colors.YELLOW,
                )
    else:
        typer.echo("Warning: UID not yet available (node may still be syncing).")


@pair_app.command("status")
def pair_status(
    hotkey: str = typer.Option(..., "--hotkey", help="Bittensor hotkey SS58 address."),
    slot: int = typer.Option(..., "--slot", help="Subnet UID assigned to the miner."),
    json_output: bool = typer.Option(False, "--json", help="Emit the raw JSON response."),
) -> None:
    """Show the verifier state for a miner pair."""
    slot_id = str(slot)
    try:
        status = fetch_pair_status(hotkey, slot_id)
    except VerifierError as exc:
        typer.secho(f"Failed to fetch pair status: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

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


@app.command("prove-lock")
def prove_lock(
    chain: int = typer.Option(..., "--chain", help="EVM chain ID for the vault transaction."),
    vault: str = typer.Option(..., "--vault", help="Vault contract address."),
    tx: str = typer.Option(..., "--tx", help="Transaction hash for the LockCreated event."),
    amount: int = typer.Option(..., "--amount", help="Lock amount in wei."),
    hotkey: str = typer.Option(..., "--hotkey", help="Bittensor hotkey SS58 address."),
    slot: int = typer.Option(..., "--slot", help="Subnet UID assigned to the miner."),
    json_output: bool = typer.Option(False, "--json", help="Emit the verifier response as JSON."),
) -> None:
    """Submit a LockProof derived from the given on-chain deposit."""
    _submit_lock_proof(
        chain=chain,
        vault=vault,
        tx_hash=tx,
        amount=amount,
        hotkey=hotkey,
        slot=str(slot),
        json_output=json_output,
    )


@app.command("claim-deposit")
def claim_deposit(
    chain: int = typer.Option(..., "--chain", help="EVM chain ID for the vault transaction."),
    vault: str = typer.Option(..., "--vault", help="Vault contract address."),
    tx: str = typer.Option(..., "--tx", help="Transaction hash for the LockCreated event."),
    amount: int = typer.Option(..., "--amount", help="Lock amount in wei."),
    hotkey: str = typer.Option(..., "--hotkey", help="Bittensor hotkey SS58 address."),
    slot: int = typer.Option(..., "--slot", help="Subnet UID assigned to the miner."),
    json_output: bool = typer.Option(False, "--json", help="Emit the verifier response as JSON."),
) -> None:
    """Alias for prove-lock for deposit-first workflows."""
    _submit_lock_proof(
        chain=chain,
        vault=vault,
        tx_hash=tx,
        amount=amount,
        hotkey=hotkey,
        slot=str(slot),
        json_output=json_output,
    )


if __name__ == "__main__":  # pragma: no cover
    app()
