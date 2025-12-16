"""Pools command - show current available pools."""

from __future__ import annotations

import typer

from .common import console

# Import pool helpers for pool_id conversion
try:
    from ...testnet.pool_ids import (
        list_pools,
        pool_id_to_chain_id,
        pool_id_to_vault_address,
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
                list_pools,
                pool_id_to_chain_id,
                pool_id_to_vault_address,
            )
        except ImportError:
            # Final fallback
            def list_pools() -> dict[str, str]:
                """Fallback: return empty dict."""
                return {}

            def pool_id_to_vault_address(pool_id: str) -> str | None:
                """Fallback: return None."""
                return None

            def pool_id_to_chain_id(pool_id: str) -> int | None:
                """Fallback: return None."""
                return None


def pools(
    json_output: bool = typer.Option(
        False, "--json", help="Emit responses as JSON."
    ),
) -> None:
    """Show all available pools with their names, IDs, vault addresses, and chain IDs.
    
    USAGE:
    ------
    cartha vault pools (or: cartha v pools)
    cartha vault pools --json (for JSON output)
    
    OUTPUT:
    -------
    - Pool names: BTCUSD, ETHUSD, EURUSD, etc.
    - Pool IDs: Full hex identifiers (0x...)
    - Vault addresses: Contract addresses for each pool
    - Chain IDs: Which blockchain network (e.g., 84532 for Base Sepolia)
    
    Use these pool names directly in 'cartha vault lock -p BTCUSD ...'
    """
    try:
        available_pools = list_pools()

        if json_output:
            # JSON output format
            import json

            pools_data = []
            for pool_name, pool_id_hex in sorted(available_pools.items()):
                vault_addr = pool_id_to_vault_address(pool_id_hex)
                chain_id = pool_id_to_chain_id(pool_id_hex)
                pool_data = {
                    "name": pool_name,
                    "pool_id": pool_id_hex,
                }
                if vault_addr:
                    pool_data["vault_address"] = vault_addr
                if chain_id:
                    pool_data["chain_id"] = chain_id
                pools_data.append(pool_data)

            console.print(json.dumps(pools_data, indent=2))
            return

        # Multi-line text output
        if not available_pools:
            console.print("[yellow]No pools available.[/]")
            return

        console.print("\n[bold cyan]Available Pools[/]\n")

        for idx, (pool_name, pool_id_hex) in enumerate(sorted(available_pools.items()), 1):
            vault_addr = pool_id_to_vault_address(pool_id_hex)
            chain_id = pool_id_to_chain_id(pool_id_hex)

            # Ensure full pool ID is displayed (normalize to ensure 0x prefix)
            pool_id_display = pool_id_hex if pool_id_hex.startswith("0x") else f"0x{pool_id_hex}"
            
            # Ensure full vault address is displayed
            vault_display = vault_addr if vault_addr else "[dim]N/A[/]"
            
            chain_display = str(chain_id) if chain_id else "[dim]N/A[/]"

            console.print(f"[bold cyan]Pool {idx}:[/] {pool_name}")
            console.print(f"  [yellow]Pool ID:[/]      {pool_id_display}")
            console.print(f"  [green]Vault Address:[/] {vault_display}")
            console.print(f"  [dim]Chain ID:[/]     {chain_display}")
            
            # Add spacing between pools except for the last one
            if idx < len(available_pools):
                console.print()

    except Exception as exc:
        console.print(f"[bold red]Error:[/] Failed to list pools: {exc}")
        raise typer.Exit(code=1)
