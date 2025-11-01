"""Cartha Typer CLI entrypoint."""

from __future__ import annotations

import json
import os
from pathlib import Path
import httpx
import typer

import bittensor as bt

APP = typer.Typer(name="cartha", help="Cartha subnet CLI.")


def _api_client(base_url: str) -> httpx.Client:
    timeout = httpx.Timeout(10.0, connect=5.0)
    return httpx.Client(base_url=base_url, timeout=timeout)


def _pairs_store() -> Path:
    path = Path.home() / ".cartha" / "pairs.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("{}\n", encoding="utf-8")
    return path


@APP.command("register")
def register(
    network: str = typer.Option("finney", "--network", help="Bittensor network name."),
    wallet_name: str = typer.Option(..., "--wallet-name", help="Coldkey wallet name."),
    hotkey_name: str = typer.Option(..., "--hotkey-name", help="Hotkey wallet name."),
    netuid: int = typer.Option(..., "--netuid", help="Subnet netuid."),
) -> None:
    """Register the provided hotkey to the Cartha subnet."""
    bt.logging.info("Starting registration flow")
    subtensor = bt.subtensor(network=network)
    wallet = bt.wallet(name=wallet_name, hotkey=hotkey_name)
    hotkey_ss58 = wallet.hotkey.ss58_address
    if not subtensor.is_hotkey_registered(hotkey_ss58, netuid):
        bt.logging.info("Hotkey not yet registered; submitting registration extrinsic")
        ok = subtensor.register(
            wallet=wallet,
            netuid=netuid,
            wait_for_finalization=True,
            cuda=True,
        )
        if not ok:
            bt.logging.error("Registration extrinsic failed")
            raise typer.Exit(code=1)

    neuron = subtensor.get_neuron_for_pubkey_and_subnet(hotkey_ss58, netuid)
    bt.logging.info(f"Registration complete - UID: {neuron.uid}")
    typer.echo(f"uid: {neuron.uid}")


@APP.command("pair-status")
def pair_status(
    verifier_url: str = typer.Option(
        "http://localhost:8000", "--verifier-url", envvar="CARTHA_VERIFIER_URL"
    ),
    hotkey: str = typer.Option(..., "--hotkey", help="Bittensor hotkey ss58 address."),
    slot: str = typer.Option(..., "--slot", help="Subnet slot UID."),
    output_json: bool = typer.Option(False, "--json", help="Emit JSON output."),
) -> None:
    """Fetch the pair status from the verifier service."""
    bt.logging.info("Fetching pair status from verifier")
    with _api_client(verifier_url) as client:
        response = client.get("/v1/pair/status", params={"hotkey": hotkey, "slot": slot})
        response.raise_for_status()
        payload = response.json()

    if output_json:
        typer.echo(json.dumps(payload, indent=2))
        return

    typer.echo(f"state: {payload.get('state', 'unknown')}")
    if payload.get("has_pwd"):
        store = _pairs_store()
        pairs = json.loads(store.read_text(encoding="utf-8"))
        key = f"{hotkey}:{slot}"
        pairs[key] = payload.get("pwd", "")
        store.write_text(json.dumps(pairs, indent=2), encoding="utf-8")
        bt.logging.info("Pair password persisted to local store")


def _resolve_evm_key(envar: str = "CARTHA_EVM_PRIVATE_KEY") -> str:
    key = os.environ.get(envar)
    if not key:
        bt.logging.error("EVM private key not configured")
        raise typer.Exit(code=1)
    return key


@APP.command("prove-lock")
def prove_lock(
    chain: int = typer.Option(..., "--chain", help="EVM chain ID."),
    vault: str = typer.Option(..., "--vault", help="Vault address."),
    tx: str = typer.Option(..., "--tx", help="Lock transaction hash."),
    amount: int = typer.Option(..., "--amount", help="Locked USDC amount (6 decimals)."),
    hotkey: str = typer.Option(..., "--hotkey", help="Bittensor hotkey ss58 address."),
    slot: str = typer.Option(..., "--slot", help="Subnet slot UID."),
    verifier_url: str = typer.Option(
        "http://localhost:8000", "--verifier-url", envvar="CARTHA_VERIFIER_URL"
    ),
) -> None:
    """Submit an EIP-712 lock proof to the verifier."""
    _resolve_evm_key()
    bt.logging.info("Submitting lock proof (stub)")
    with _api_client(verifier_url) as client:
        response = client.post(
            "/v1/proofs/lock",
            json={
                "vaultAddress": vault,
                "minerEvmAddress": "0x0",
                "minerHotkey": hotkey,
                "slotUID": slot,
                "chainId": chain,
                "txHash": tx,
                "amount": str(amount),
                "pwd": "0x0",
            },
        )
        response.raise_for_status()
    typer.echo("Lock proof submitted")


@APP.command("claim-deposit")
def claim_deposit(
    chain: int = typer.Option(..., "--chain", help="EVM chain ID."),
    vault: str = typer.Option(..., "--vault", help="Vault address."),
    tx: str = typer.Option(..., "--tx", help="Lock transaction hash."),
    amount: int = typer.Option(..., "--amount", help="Locked USDC amount (6 decimals)."),
    hotkey: str = typer.Option(..., "--hotkey", help="Bittensor hotkey ss58 address."),
    slot: str = typer.Option(..., "--slot", help="Subnet slot UID."),
    verifier_url: str = typer.Option(
        "http://localhost:8000", "--verifier-url", envvar="CARTHA_VERIFIER_URL"
    ),
) -> None:
    """Alias for prove-lock to support deposit-first flow."""
    prove_lock(chain, vault, tx, amount, hotkey, slot, verifier_url)


def main() -> None:
    """Entrypoint for console_scripts."""
    APP()


if __name__ == "__main__":  # pragma: no cover
    main()
