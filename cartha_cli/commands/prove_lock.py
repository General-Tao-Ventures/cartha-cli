"""Lock command - create new lock positions with verifier-signed EIP-712 LockRequest."""

from __future__ import annotations

import time
from decimal import Decimal
from pathlib import Path
from typing import Any

import typer
from rich import box
from rich.prompt import Confirm
from rich.table import Table
from web3 import Web3

from ..config import settings
from ..pair import build_pair_auth_payload, get_uid_from_hotkey
from ..utils import normalize_hex, usdc_to_base_units
from ..verifier import (
    VerifierError,
    get_lock_status,
    request_lock_signature,
    verify_hotkey,
)
from ..wallet import load_wallet
from .common import console, exit_with_error, handle_unexpected_exception

# Import pool helpers for pool_id conversion
try:
    from ...testnet.pool_ids import (
        format_pool_id,
        list_pools,
        pool_id_to_name,
        pool_name_to_id,
    )
except ImportError:
    # Fallback if running from different context
    import sys
    from pathlib import Path

    # Try adding parent directory to path
    testnet_dir = Path(__file__).parent.parent.parent / "testnet"
    if testnet_dir.exists():
        sys.path.insert(0, str(testnet_dir.parent))
        try:
            from testnet.pool_ids import (
                format_pool_id,
                list_pools,
                pool_id_to_name,
                pool_name_to_id,
            )
        except ImportError:
            # Final fallback
            def pool_name_to_id(pool_name: str) -> str:
                """Fallback: encode pool name as hex."""
                name_bytes = pool_name.encode("utf-8")
                padded = name_bytes.ljust(32, b"\x00")
                return "0x" + padded.hex()
            
            def pool_id_to_name(pool_id: str) -> str | None:
                """Fallback: try to decode."""
                try:
                    hex_str = pool_id.lower().removeprefix("0x")
                    pool_bytes = bytes.fromhex(hex_str)
                    name = pool_bytes.rstrip(b"\x00").decode("utf-8", errors="ignore")
                    return name if name and name.isprintable() else None
                except Exception:
                    return None
            
            def format_pool_id(pool_id: str) -> str:
                """Fallback: return pool_id as-is."""
                return pool_id
            
            def list_pools() -> dict[str, str]:
                """Fallback: return empty dict."""
                return {}


def prove_lock(
    coldkey: str | None = typer.Option(
        None,
        "--coldkey",
        help="Coldkey wallet name (defaults to 'default')",
        show_default=False,
    ),
    hotkey: str | None = typer.Option(
        None,
        "--hotkey",
        help="Hotkey name (defaults to 'default')",
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
    pool_id: str | None = typer.Option(
        None,
        "--pool-id",
        help="Pool ID (readable name or hex string, e.g., 'BTC/USD' or '0x...')",
        show_default=False,
    ),
    amount: str | None = typer.Option(
        None,
        "--amount",
        help="Lock amount in USDC (e.g. 250.5). Auto-detects if normalized USDC or base units (>1e9).",
        show_default=False,
    ),
    lock_days: int | None = typer.Option(
        None,
        "--lock-days",
        help="Lock duration in days (e.g., 365)",
        show_default=False,
    ),
    owner: str | None = typer.Option(
        None,
        "--owner",
        help="EVM address that will own the lock position (defaults to prompting)",
        show_default=False,
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit responses as JSON."
    ),
) -> None:
    """Create a new lock position with verifier-signed EIP-712 LockRequest.
    
    Flow:
    1. Check registration on subnet 35
    2. Authenticate with Bittensor hotkey signature
    3. Request EIP-712 LockRequest signature from verifier
    4. Display transaction data for user to execute in MetaMask
    5. Poll for lock status until verified
    """
    try:
        # Step 1: Collect coldkey and hotkey
        if coldkey is None:
            coldkey = typer.prompt("Coldkey wallet name", default="default")
        if hotkey is None:
            hotkey = typer.prompt("Hotkey name", default="default")

        # Load wallet to get hotkey SS58 address
        wallet = load_wallet(coldkey, hotkey)
        hotkey_ss58 = wallet.hotkey.ss58_address

        console.print(f"\n[bold cyan]Checking registration...[/]")
        console.print(f"[dim]Hotkey:[/] {hotkey_ss58}")

        # Step 2: Check registration via Bittensor network (same as other commands)
        try:
            with console.status(
                "[bold cyan]Checking miner registration status...[/]",
                spinner="dots",
            ):
                uid = get_uid_from_hotkey(
                    network=settings.network,
                    netuid=settings.netuid,
                    hotkey=hotkey_ss58,
                )

            if uid is None:
                console.print(
                    "[bold red]Error:[/] Hotkey is not registered or has been deregistered "
                    f"on netuid {settings.netuid} ({settings.network} network)."
                )
                console.print(
                    "[yellow]Please register your hotkey first using 'cartha miner register'.[/]"
                )
                raise typer.Exit(code=1)

            console.print(f"[bold green]✓ Registered[/] - UID: {uid}")
        except typer.Exit:
            raise
        except Exception as exc:
            handle_unexpected_exception("Registration check failed", exc)

        # Step 3: Generate Bittensor signature for authentication
        console.print(f"\n[bold cyan]Authenticating with Bittensor hotkey...[/]")
        try:
            auth_payload = build_pair_auth_payload(
                network=settings.network,
                netuid=settings.netuid,
                slot=str(uid),
                hotkey=hotkey_ss58,
                wallet_name=coldkey,
                wallet_hotkey=hotkey,
                skip_metagraph_check=True,  # Already checked via verifier
                challenge_prefix="cartha-lock",
            )
        except Exception as exc:
            handle_unexpected_exception("Failed to generate Bittensor signature", exc)

        # Step 4: Verify hotkey and get session token
        try:
            auth_result = verify_hotkey(
                hotkey=hotkey_ss58,
                signature=auth_payload["signature"],
                message=auth_payload["message"],
            )
            session_token = auth_result["session_token"]
            expires_at = auth_result["expires_at"]
            console.print(
                f"[bold green]✓ Authenticated[/] - Session expires at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(expires_at))}"
            )
        except VerifierError as exc:
            exit_with_error(f"Authentication failed: {exc}")
        except Exception as exc:
            handle_unexpected_exception("Authentication failed", exc)

        # Step 5: Collect lock parameters
        console.print(f"\n[bold cyan]Collecting lock parameters...[/]")

        # Chain ID
        if chain is None:
            while True:
                try:
                    chain_input = typer.prompt("Chain ID", show_default=False)
                    chain = int(chain_input)
                    if chain <= 0:
                        console.print(
                            "[bold red]Error:[/] Chain ID must be a positive integer"
                        )
                        continue
                    break
                except ValueError:
                    console.print("[bold red]Error:[/] Chain ID must be a valid integer")

        # Vault address
        if vault is None:
            while True:
                vault = typer.prompt("Vault contract address", show_default=False)
                if Web3.is_address(vault):
                    vault = Web3.to_checksum_address(vault)
                    break
                console.print(
                    "[bold red]Error:[/] Vault address must be a valid EVM address (0x...)"
                )

        # Pool ID
        if pool_id is None:
            # Show available pools if we have them
            available_pools = list_pools()
            if available_pools:
                console.print("\n[bold cyan]Available pools:[/]")
                for pool_name, pool_id_hex in sorted(available_pools.items()):
                    console.print(f"  - {pool_name}: {format_pool_id(pool_id_hex)}")
                console.print()

        while True:
                pool_input = typer.prompt(
                    "Pool ID (name or hex string)", show_default=False
                )
                pool_id_clean = pool_input.strip()

                # Check if it's a readable pool name
                pool_id_upper = pool_id_clean.upper()
                if available_pools and pool_id_upper in available_pools:
                    pool_id = pool_name_to_id(pool_id_upper).lower()
                    console.print(
                        f"[dim]Converted pool name to ID:[/] {pool_id_upper} → {format_pool_id(pool_id)}"
                    )
                    break
                # Check if it's a hex string
                elif pool_id_clean.startswith("0x") and len(pool_id_clean) == 66:
                    pool_id = pool_id_clean.lower()
                    break
                else:
                    # Try to normalize
                    pool_id_normalized = normalize_hex(pool_id_clean).lower()
                    if len(pool_id_normalized) == 66:
                        pool_id = pool_id_normalized
                        break
                    console.print(
                        "[bold red]Error:[/] Pool ID must be a recognized pool name or a 66-character hex string (0x...)"
                    )

        # Normalize pool_id
        if not pool_id.startswith("0x"):
            pool_id = "0x" + pool_id
        pool_id = pool_id.lower()

    # Amount
        amount_base_units: int | None = None
        if amount is None:
            while True:
                try:
                    amount_input = typer.prompt(
                        "Lock amount in USDC (e.g. 250.5)", show_default=False
                    )
                    amount_base_units = usdc_to_base_units(amount_input)
                    if amount_base_units <= 0:
                        console.print("[bold red]Error:[/] Amount must be positive")
                        continue
                    break
                except Exception as exc:
                    console.print(f"[bold red]Error:[/] Invalid amount: {exc}")
        else:
            try:
                amount_as_int = int(float(amount))
                if amount_as_int >= 1_000_000_000:
                    amount_base_units = amount_as_int
                else:
                    amount_base_units = usdc_to_base_units(amount)
            except (ValueError, Exception):
                amount_base_units = usdc_to_base_units(amount)

        # Lock days
        if lock_days is None:
            while True:
                try:
                    lock_days_input = typer.prompt(
                        "Lock duration in days (e.g., 365)", show_default=False
                    )
                    lock_days = int(lock_days_input)
                    if lock_days <= 0:
                        console.print(
                            "[bold red]Error:[/] Lock days must be positive"
                        )
                        continue
                    if lock_days > 1825:  # 5 years max
                        console.print(
                            "[bold red]Error:[/] Lock days cannot exceed 1825 (5 years)"
                        )
                        continue
                    break
                except ValueError:
                    console.print("[bold red]Error:[/] Lock days must be a valid integer")

        # Owner (EVM address)
        if owner is None:
            while True:
                owner = typer.prompt("EVM address (owner)", show_default=False)
                if Web3.is_address(owner):
                    owner = Web3.to_checksum_address(owner)
                    break
                console.print(
                    "[bold red]Error:[/] EVM address must be a valid address (0x...)"
                )
        else:
            if not Web3.is_address(owner):
                exit_with_error("Invalid EVM address format")
            owner = Web3.to_checksum_address(owner)

        # Step 6: Request EIP-712 LockRequest signature from verifier
        console.print(f"\n[bold cyan]Requesting signature from verifier...[/]")
        try:
            sig_result = request_lock_signature(
                session_token=session_token,
                pool_id=pool_id,
                amount=amount_base_units,
                lock_days=lock_days,
                hotkey=hotkey_ss58,
                miner_slot=str(uid),
                uid=str(uid),
                owner=owner,
                chain_id=chain,
                vault_address=vault,
            )
            signature = sig_result["signature"]
            timestamp = sig_result["timestamp"]
            nonce = sig_result["nonce"]
            expires_at_sig = sig_result["expiresAt"]
            approve_tx = sig_result["approveTx"]
            lock_tx = sig_result["lockTx"]

            console.print(f"[bold green]✓ Signature received[/]")
            console.print(f"[dim]Expires at:[/] {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(expires_at_sig))}")
        except VerifierError as exc:
            exit_with_error(f"Failed to request signature: {exc}")
        except Exception as exc:
            handle_unexpected_exception("Signature request failed", exc)

        # Step 7: Display lock details and get confirmation
        console.print(f"\n[bold cyan]Lock Details:[/]")
        summary_table = Table(show_header=False, box=box.SIMPLE)
        summary_table.add_column(style="cyan")
        summary_table.add_column(style="yellow")

        # Show pool name if available
        pool_name = pool_id_to_name(pool_id)
        pool_display = (
            pool_name.upper() if pool_name else format_pool_id(pool_id)
        )
        summary_table.add_row("Pool", pool_display)

        human_amount = Decimal(amount_base_units) / Decimal(10**6)
        amount_str = f"{human_amount:.6f}".rstrip("0").rstrip(".")
        summary_table.add_row("Amount", f"{amount_str} USDC ({amount_base_units} base units)")

        summary_table.add_row("Lock Days", str(lock_days))
        summary_table.add_row("Owner (EVM)", owner)
        summary_table.add_row("Hotkey", hotkey_ss58)
        summary_table.add_row("UID", str(uid))
        summary_table.add_row("Chain ID", str(chain))
        summary_table.add_row("Vault", vault)

        # Calculate unlock date
        unlock_timestamp = int(time.time()) + (lock_days * 24 * 60 * 60)
        unlock_date = time.strftime("%Y-%m-%d", time.gmtime(unlock_timestamp))
        summary_table.add_row("Unlock Date", unlock_date)

        console.print(summary_table)
        console.print()

        if not Confirm.ask(
            "[bold yellow]Proceed with lock creation?[/]", default=True
        ):
            console.print("[bold yellow]Cancelled.[/]")
            raise typer.Exit(code=0)

        # Step 8: Display transaction data
        console.print(f"\n[bold cyan]Transaction Data[/]")
        console.print(
            "\n[bold yellow]⚠️  Execute these transactions in MetaMask:[/]\n"
        )

        console.print("[bold]1. Approve USDC:[/]")
        console.print(f"   To: {approve_tx['to']}")
        console.print(f"   Data: {approve_tx['data']}")
        console.print()

        console.print("[bold]2. Lock Position:[/]")
        console.print(f"   To: {lock_tx['to']}")
        console.print(f"   Data: {lock_tx['data']}")
        console.print()

        console.print(
            "[bold yellow]⚠️  After executing the transactions, the verifier will automatically detect the lock.[/]"
        )
        console.print(
            "[dim]You can check status with: cartha-vault lock-status --tx <tx_hash>[/]"
        )

        # Step 9: Optionally poll for status
        if Confirm.ask(
            "\n[bold cyan]Poll for lock status after transaction?[/] (Enter transaction hash when ready)",
            default=False,
        ):
            while True:
                tx_hash = typer.prompt(
                    "Transaction hash (0x...)", show_default=False
                )
                tx_hash_normalized = normalize_hex(tx_hash)
                if len(tx_hash_normalized) == 66:
                    break
                console.print(
                    "[bold red]Error:[/] Transaction hash must be 32 bytes (0x + 64 hex characters)"
                )

            console.print("\n[bold cyan]Polling for lock status...[/]")
            max_polls = 30
            poll_interval = 5  # seconds

            for poll_num in range(max_polls):
                try:
                    status_result = get_lock_status(tx_hash=tx_hash_normalized)
                    if status_result.get("verified"):
                        console.print("\n[bold green]✓ Lock verified![/]")
                        console.print(
                            f"[bold cyan]Lock ID:[/] {status_result.get('lockId', 'N/A')}"
                        )
                        console.print(
                            f"[bold cyan]Added to epoch:[/] {status_result.get('addedToEpoch', 'N/A')}"
                        )
                        break
                    else:
                        if poll_num < max_polls - 1:
                            console.print(
                                f"[dim]Waiting for verification... ({poll_num + 1}/{max_polls})[/]"
                            )
                            time.sleep(poll_interval)
                        else:
                            console.print(
                                "\n[yellow]Lock not yet verified. The verifier will process it automatically.[/]"
                            )
                            console.print(
                                f"[dim]Message: {status_result.get('message', 'N/A')}[/]"
                            )
                except VerifierError as exc:
                    if poll_num < max_polls - 1:
                        console.print(
                            f"[yellow]Status check failed (will retry): {exc}[/]"
                        )
                        time.sleep(poll_interval)
                    else:
                        console.print(
                            f"\n[yellow]Final status check failed: {exc}[/]"
                        )
                        console.print(
                            "[dim]The verifier will process the lock automatically.[/]"
                        )
                except Exception as exc:
                    console.print(f"\n[yellow]Status check error: {exc}[/]")
                    console.print(
                        "[dim]The verifier will process the lock automatically.[/]"
                    )
                    break

        console.print("\n[bold green]✓ Lock flow complete![/]")

    except typer.Exit:
        raise
    except Exception as exc:
        handle_unexpected_exception("Lock creation failed", exc)
