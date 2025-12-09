"""Lock command - create new lock positions with verifier-signed EIP-712 LockRequest."""

from __future__ import annotations

import time
from decimal import Decimal
from pathlib import Path
from typing import Any

import typer
from rich import box
from rich.prompt import Confirm
from rich.status import Status
from rich.table import Table
from web3 import Web3

from ..config import settings
from ..pair import build_pair_auth_payload, get_uid_from_hotkey
from ..utils import normalize_hex, usdc_to_base_units
from ..verifier import (
    VerifierError,
    get_lock_status,
    process_lock_transaction,
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
        pool_id_to_chain_id,
        pool_id_to_name,
        pool_id_to_vault_address,
        pool_name_to_id,
        vault_address_to_chain_id,
        vault_address_to_pool_id,
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
                pool_id_to_chain_id,
                pool_id_to_name,
                pool_id_to_vault_address,
                pool_name_to_id,
                vault_address_to_chain_id,
                vault_address_to_pool_id,
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
            
            def pool_id_to_vault_address(pool_id: str) -> str | None:
                """Fallback: return None."""
                return None
            
            def vault_address_to_pool_id(vault_address: str) -> str | None:
                """Fallback: return None."""
                return None
            
            def pool_id_to_chain_id(pool_id: str) -> int | None:
                """Fallback: return None."""
                return None
            
            def vault_address_to_chain_id(vault_address: str) -> int | None:
                """Fallback: return None."""
                return None


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

        # Chain ID - will be auto-detected after pool_id/vault is selected
        # We'll set it after vault matching

        # Pool ID (collect first, then auto-match vault)
        available_pools = list_pools()
        if pool_id is None:
            # Show available pools if we have them
            if available_pools:
                console.print("\n[bold cyan]Available pools:[/]")
                for pool_name, pool_id_hex in sorted(available_pools.items()):
                    vault_addr = pool_id_to_vault_address(pool_id_hex)
                    if vault_addr:
                        console.print(
                            f"  - {pool_name}: {format_pool_id(pool_id_hex)} "
                            f"[dim](Vault: {vault_addr})[/]"
                        )
                    else:
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

        # Auto-match vault address from pool ID
        if vault is None:
            auto_vault = pool_id_to_vault_address(pool_id)
            if auto_vault:
                vault = Web3.to_checksum_address(auto_vault)
                pool_name = pool_id_to_name(pool_id)
                console.print(
                    f"[bold green]✓ Auto-matched vault[/] - {pool_name or 'Pool'} → {vault}"
                )
            else:
                # Fallback: prompt for vault if no mapping found
                console.print(
                    "[yellow]⚠ No vault mapping found for this pool ID. Please provide vault address.[/]"
                )
                while True:
                    vault = typer.prompt("Vault contract address", show_default=False)
                    if Web3.is_address(vault):
                        vault = Web3.to_checksum_address(vault)
                        break
                    console.print(
                        "[bold red]Error:[/] Vault address must be a valid EVM address (0x...)"
                    )
        else:
            # Vault was provided, verify it matches pool ID if possible
            if Web3.is_address(vault):
                vault = Web3.to_checksum_address(vault)
                expected_pool_id = vault_address_to_pool_id(vault)
                if expected_pool_id and expected_pool_id.lower() != pool_id.lower():
                    pool_name = pool_id_to_name(pool_id)
                    expected_pool_name = pool_id_to_name(expected_pool_id)
                    console.print(
                        f"[bold yellow]⚠ Warning:[/] Vault {vault} is mapped to pool "
                        f"{expected_pool_name or expected_pool_id}, but you selected "
                        f"{pool_name or pool_id}"
                    )
                    if not Confirm.ask(
                        "[yellow]Continue anyway?[/]", default=False
                    ):
                        raise typer.Exit(code=1)
            else:
                exit_with_error("Invalid vault address format")
        
        # Auto-match chain ID from pool ID or vault address
        if chain is None:
            # Try to get chain ID from pool ID first
            auto_chain_id = None
            try:
                auto_chain_id = pool_id_to_chain_id(pool_id)
            except NameError:
                # Function not available - this shouldn't happen if imports worked
                # But handle gracefully by trying to import it
                try:
                    from testnet.pool_ids import pool_id_to_chain_id
                    auto_chain_id = pool_id_to_chain_id(pool_id)
                except ImportError:
                    pass
            
            if not auto_chain_id:
                # Fallback: try to get from vault address
                try:
                    auto_chain_id = vault_address_to_chain_id(vault)
                except NameError:
                    try:
                        from testnet.pool_ids import vault_address_to_chain_id
                        auto_chain_id = vault_address_to_chain_id(vault)
                    except ImportError:
                        pass
            
            if auto_chain_id:
                chain = auto_chain_id
                chain_name = "Base Sepolia" if chain == 84532 else f"Chain {chain}"
                console.print(
                    f"[bold green]✓ Auto-matched chain ID[/] - {chain_name} (chain ID: {chain})"
                )
            else:
                # Fallback: prompt for chain ID if no mapping found
                console.print(
                    "[yellow]⚠ No chain ID mapping found. Please provide chain ID.[/]"
                )
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
        else:
            # Chain ID was provided, verify it matches vault if possible
            expected_chain_id = vault_address_to_chain_id(vault)
            if expected_chain_id and expected_chain_id != chain:
                chain_name = "Base Sepolia" if expected_chain_id == 84532 else f"Chain {expected_chain_id}"
                console.print(
                    f"[bold yellow]⚠ Warning:[/] Vault {vault} is on {chain_name} (chain ID: {expected_chain_id}), "
                    f"but you specified chain ID {chain}"
                )
                if not Confirm.ask(
                    "[yellow]Continue anyway?[/]", default=False
                ):
                    raise typer.Exit(code=1)

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

        # Step 8: Display transaction data - Phase 1: Approve
        console.print(f"\n[bold cyan]Transaction Data[/]")
        console.print(
            "\n[bold yellow]⚠️  Execute these transactions to complete your lock:[/]\n"
        )

        # USDC contract address for Base Sepolia
        usdc_contract_address = "0x2340D09c348930A76c8c2783EDa8610F699A51A8"
        
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
        console.print("[bold]Phase 1: Approve USDC (via BaseScan)[/]")
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
        console.print()
        console.print("[bold]Step-by-step instructions:[/]")
        console.print("  1. Go to: [cyan]https://sepolia.basescan.org/address/0x2340D09c348930A76c8c2783EDa8610F699A51A8[/]")
        console.print("  2. Click [bold]'Contract'[/] tab")
        console.print("  3. Click [bold]'Write Contract'[/] tab")
        console.print("  4. Click [bold]'Connect to Web3'[/] button and connect your EVM wallet")
        console.print(f"     (Use the same wallet address as the owner: [cyan]{owner}[/])")
        console.print("  5. Find and click [bold]'1. approve'[/] function")
        console.print("  6. Fill in the fields:")
        console.print()
        console.print("[bold]Function: approve[/]")
        console.print("[bold]Parameters:[/]")
        console.print(f"   [yellow]spender[/] (address): {vault}")
        console.print(f"   [yellow]amount[/] (uint256): {amount_base_units}")
        console.print()
        console.print("  7. Click [bold]'Write'[/] and confirm succeed with the transaction hash")
        console.print()

        # Wait for user confirmation before showing Phase 2
        if not Confirm.ask(
            "\n[bold yellow]Have you completed the approve transaction?[/] (Type 'yes' to continue to Phase 2)",
            default=False
        ):
            console.print("[bold yellow]You can continue with Phase 2 later. The signature will expire in 5 minutes.[/]")
            raise typer.Exit(code=0)

        # Step 9: Display Phase 2: Lock Position
        console.print()
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
        console.print("[bold]Phase 2: Lock Position (via BaseScan)[/]")
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]")
        console.print()
        # Verify vault address matches what we expect
        if lock_tx['to'].lower() != vault.lower():
            console.print(
                f"[bold yellow]⚠ Warning:[/] Transaction vault address ({lock_tx['to']}) "
                f"does not match selected vault ({vault})"
            )
        console.print("[bold]Vault Contract Address:[/]")
        console.print(f"   {lock_tx['to']}")
        console.print()
        console.print("[bold]Step-by-step instructions:[/]")
        console.print(f"  1. Go to: [cyan]https://sepolia.basescan.org/address/{lock_tx['to']}[/]")
        console.print("  2. Click [bold]'Contract'[/] tab")
        console.print("  3. Click [bold]'Write as Proxy'[/] tab")
        console.print("  4. Click [bold]'Connect to Web3'[/] button and connect your EVM wallet")
        console.print(f"     (Use the same wallet address as the owner: [cyan]{owner}[/])")
        console.print("  5. Find and click [bold]'8. lock'[/] function")
        console.print("  6. Fill in the fields:")
        console.print()
        console.print("[bold]Function: lock[/]")
        console.print("[bold]Parameters:[/]")
        
        # Calculate hotkey bytes32 (keccak256 of SS58 string)
        hotkey_bytes = hotkey_ss58.encode("utf-8")
        hotkey_bytes32 = Web3.keccak(hotkey_bytes)
        # Ensure single 0x prefix (hex() doesn't include 0x)
        hotkey_hex = hotkey_bytes32.hex()
        if not hotkey_hex.startswith("0x"):
            hotkey_hex = "0x" + hotkey_hex
        
        # Convert pool_id to bytes32 hex if needed
        pool_id_normalized = pool_id.lower().strip()
        if not pool_id_normalized.startswith("0x"):
            pool_id_normalized = "0x" + pool_id_normalized
        if len(pool_id_normalized) == 42:
            # Legacy address format: pad to bytes32
            hex_part = pool_id_normalized[2:]
            padded_hex = "0" * 24 + hex_part
            pool_id_normalized = "0x" + padded_hex
        
        # Ensure signature has single 0x prefix
        signature_normalized = signature.strip()
        if signature_normalized.startswith("0x0x"):
            # Remove double 0x prefix
            signature_normalized = signature_normalized[2:]
        elif not signature_normalized.startswith("0x"):
            signature_normalized = "0x" + signature_normalized
        
        console.print(f"   [yellow]poolId_[/] (bytes32): {pool_id_normalized}")
        console.print(f"   [yellow]amount[/] (uint256): {amount_base_units}")
        console.print(f"   [yellow]lockDays[/] (uint64): {lock_days}")
        console.print(f"   [yellow]hotkey[/] (bytes32): {hotkey_hex}")
        console.print(f"   [yellow]timestamp[/] (uint256): {timestamp}")
        console.print(f"   [yellow]signature[/] (bytes): {signature_normalized}")
        console.print()
        console.print("  7. Click [bold]'Write'[/], confirm the  success transaction and copy the transaction hash")
        console.print()

        console.print(
            "[dim]The verifier will automatically detect the lock after you execute the transactions.[/]"
        )
        console.print(
            f"[dim]You can also check status with: [bold]cartha miner status --wallet-name {coldkey} --wallet-hotkey {hotkey}[/][/]"
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

            console.print()  # Empty line before polling
            max_polls = 10
            poll_interval = 5  # seconds

            with Status(
                "[bold cyan]Polling for lock status...[/]",
                console=console,
                spinner="dots",
            ) as status:
                for poll_num in range(max_polls):
                    try:
                        status.update(
                            f"[bold cyan]Checking lock status... (attempt {poll_num + 1}/{max_polls})[/]"
                        )
                        status_result = get_lock_status(tx_hash=tx_hash_normalized)
                        if status_result.get("verified"):
                            status.stop()
                            console.print("\n[bold green]✓ Lock verified![/]")
                            console.print(
                                f"[bold cyan]Lock ID:[/] {status_result.get('lockId', 'N/A')}"
                            )
                            console.print(
                                f"[bold cyan]Added to epoch:[/] {status_result.get('addedToEpoch', 'N/A')}"
                            )
                            break
                        else:
                            # Check if event was found on-chain but not yet processed
                            message = status_result.get("message", "")
                            if "found on-chain but not yet processed" in message.lower():
                                # Try to trigger immediate processing
                                try:
                                    status.update(
                                        f"[bold cyan]Lock detected on-chain, triggering immediate processing... (attempt {poll_num + 1}/{max_polls})[/]"
                                    )
                                    process_result = process_lock_transaction(tx_hash=tx_hash_normalized)
                                    if process_result.get("success"):
                                        # Processing succeeded, check status again
                                        status.update(
                                            f"[bold cyan]Processing triggered, verifying... (attempt {poll_num + 1}/{max_polls})[/]"
                                        )
                                        time.sleep(1)  # Brief delay for database commit
                                        status_result = get_lock_status(tx_hash=tx_hash_normalized)
                                        if status_result.get("verified"):
                                            status.stop()
                                            console.print("\n[bold green]✓ Lock verified![/]")
                                            console.print(
                                                f"[bold cyan]Lock ID:[/] {status_result.get('lockId', 'N/A')}"
                                            )
                                            console.print(
                                                f"[bold cyan]Added to epoch:[/] {status_result.get('addedToEpoch', 'N/A')}"
                                            )
                                            break
                                    else:
                                        # Processing didn't succeed (e.g., couldn't match to miner)
                                        if poll_num < max_polls - 1:
                                            status.update(
                                                f"[bold cyan]Processing failed, waiting for automatic detection... (attempt {poll_num + 1}/{max_polls})[/]"
                                            )
                                            time.sleep(poll_interval)
                                        else:
                                            status.stop()
                                            console.print(
                                                "\n[yellow]Lock detected on-chain but processing failed.[/]"
                                            )
                                            console.print(
                                                "[dim]The verifier will process it automatically within the next hour.[/]"
                                            )
                                            console.print(
                                                f"[dim]You can check status later with: [bold]cartha miner status --wallet-name {coldkey} --wallet-hotkey {hotkey}[/][/]"
                                            )
                                except VerifierError as process_exc:
                                    # Processing failed, continue polling
                                    if poll_num < max_polls - 1:
                                        status.update(
                                            f"[bold cyan]Processing failed, waiting for automatic detection... (attempt {poll_num + 1}/{max_polls})[/]"
                                        )
                                        time.sleep(poll_interval)
                                    else:
                                        status.stop()
                                        console.print(
                                            "\n[yellow]Lock detected on-chain but processing failed.[/]"
                                        )
                                        console.print(
                                            "[dim]The verifier will process it automatically within the next hour.[/]"
                                        )
                                        console.print(
                                            f"[dim]You can check status later with: [bold]cartha miner status --wallet-name {coldkey} --wallet-hotkey {hotkey}[/][/]"
                                        )
                                except Exception as process_exc:
                                    # Unexpected error, continue polling
                                    if poll_num < max_polls - 1:
                                        status.update(
                                            f"[bold cyan]Waiting for verification... (attempt {poll_num + 1}/{max_polls})[/]"
                                        )
                                        time.sleep(poll_interval)
                                    else:
                                        status.stop()
                                        console.print(
                                            "\n[yellow]Lock detected on-chain but not yet processed by verifier.[/]"
                                        )
                                        console.print(
                                            "[dim]The verifier polls every hour and will process it automatically.[/]"
                                        )
                                        console.print(
                                            f"[dim]You can check status later with: [bold]cartha miner status --wallet-name {coldkey} --wallet-hotkey {hotkey}[/][/]"
                                        )
                                # If we didn't break, continue to next iteration
                                if poll_num < max_polls - 1:
                                    continue
                            else:
                                if poll_num < max_polls - 1:
                                    status.update(
                                        f"[bold cyan]Waiting for verification... (attempt {poll_num + 1}/{max_polls})[/]"
                                    )
                                    time.sleep(poll_interval)
                                else:
                                    status.stop()
                                    console.print(
                                        "\n[yellow]Lock not yet verified. The verifier will process it automatically.[/]"
                                    )
                                    console.print(
                                        f"[dim]Message: {message or 'N/A'}[/]"
                                    )
                    except VerifierError as exc:
                        if poll_num < max_polls - 1:
                            # Truncate long error messages to keep single line clean
                            error_msg = str(exc)
                            if len(error_msg) > 50:
                                error_msg = error_msg[:47] + "..."
                            status.update(
                                f"[yellow]Retrying... (attempt {poll_num + 1}/{max_polls})[/] [dim]{error_msg}[/]"
                            )
                            time.sleep(poll_interval)
                        else:
                            status.stop()
                            console.print(
                                f"\n[yellow]Final status check failed: {exc}[/]"
                            )
                            console.print(
                                "[dim]The verifier will process the lock automatically.[/]"
                            )
                    except Exception as exc:
                        status.stop()
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
