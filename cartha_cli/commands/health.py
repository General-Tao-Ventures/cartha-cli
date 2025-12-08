"""Health check command - verify CLI connectivity and configuration."""

from __future__ import annotations

import time
from typing import Any

import bittensor as bt
import typer
from rich.console import Console
from rich.table import Table

from ..config import settings
from ..verifier import VerifierError, _build_url, _request
from .common import console

import requests  # type: ignore[import-untyped]


def health_check(
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed information for each check."
    ),
) -> None:
    """Check CLI health: verifier connectivity, Bittensor network, and configuration.
    
    This command verifies that all components needed for the CLI are working correctly.
    """
    checks_passed = 0
    checks_failed = 0
    checks_warning = 0
    
    results: list[dict[str, Any]] = []
    
    # Check 1: Verifier connectivity
    console.print("\n[bold cyan]━━━ Health Check ━━━[/]")
    console.print()
    
    verifier_url = settings.verifier_url
    console.print(f"[bold]Checking verifier connectivity...[/]")
    console.print(f"[dim]URL: {verifier_url}[/]")
    
    verifier_ok = False
    verifier_status = "Unknown"
    verifier_latency_ms = None
    
    try:
        start_time = time.time()
        # Try to hit a simple endpoint (health or root)
        try:
            # Try /health endpoint first
            health_url = _build_url("/health")
            response = requests.get(health_url, timeout=(5, 10))
            if response.status_code == 200:
                verifier_ok = True
                verifier_status = "Healthy"
            elif response.status_code == 404:
                # 404 is OK - means verifier is up but endpoint doesn't exist
                # Try a simple GET request to verify connectivity
                try:
                    _request("GET", "/v1/miner/status", params={"hotkey": "test", "slot": "0"}, retry=False)
                    verifier_ok = True
                    verifier_status = "Reachable (no /health endpoint)"
                except VerifierError as exc:
                    # 404 or 400 means verifier is reachable, just wrong params
                    if exc.status_code in (400, 404):
                        verifier_ok = True
                        verifier_status = "Reachable"
                    else:
                        verifier_status = f"Error: {exc}"
            else:
                verifier_status = f"HTTP {response.status_code}"
        except requests.RequestException as exc:
            # Connection error - verifier is not reachable
            verifier_status = f"Connection error: {exc}"
        except VerifierError as exc:
            # This shouldn't happen for /health, but handle it anyway
            if exc.status_code == 404:
                verifier_ok = True
                verifier_status = "Reachable (no /health endpoint)"
            else:
                verifier_status = f"Error: {exc}"
        except Exception as exc:
            verifier_status = f"Error: {exc}"
        
        if verifier_ok:
            latency_ms = int((time.time() - start_time) * 1000)
            verifier_latency_ms = latency_ms
            console.print(f"[bold green]✓ Verifier is reachable[/] ({latency_ms}ms)")
            checks_passed += 1
        else:
            console.print(f"[bold red]✗ Verifier check failed[/]: {verifier_status}")
            checks_failed += 1
        
        results.append({
            "name": "Verifier Connectivity",
            "status": "pass" if verifier_ok else "fail",
            "details": verifier_status,
            "latency_ms": verifier_latency_ms,
        })
    except Exception as exc:
        console.print(f"[bold red]✗ Verifier check error[/]: {exc}")
        checks_failed += 1
        results.append({
            "name": "Verifier Connectivity",
            "status": "fail",
            "details": str(exc),
        })
    
    # Check 2: Bittensor network connectivity
    console.print()
    console.print(f"[bold]Checking Bittensor network...[/]")
    console.print(f"[dim]Network: {settings.network}, NetUID: {settings.netuid}[/]")
    
    bt_ok = False
    bt_status = "Unknown"
    bt_latency_ms = None
    
    try:
        start_time = time.time()
        subtensor = bt.subtensor(network=settings.network)
        current_block = subtensor.get_current_block()
        latency_ms = int((time.time() - start_time) * 1000)
        bt_latency_ms = latency_ms
        
        if current_block and current_block > 0:
            bt_ok = True
            bt_status = f"Connected (block: {current_block})"
            console.print(f"[bold green]✓ Bittensor network is reachable[/] ({latency_ms}ms, block: {current_block})")
            checks_passed += 1
        else:
            bt_status = "Connected but invalid block number"
            console.print(f"[bold yellow]⚠ Bittensor network check warning[/]: {bt_status}")
            checks_warning += 1
    except Exception as exc:
        bt_status = f"Error: {exc}"
        console.print(f"[bold red]✗ Bittensor network check failed[/]: {exc}")
        checks_failed += 1
    
    results.append({
        "name": "Bittensor Network",
        "status": "pass" if bt_ok else ("warning" if checks_warning > 0 else "fail"),
        "details": bt_status,
        "latency_ms": bt_latency_ms,
    })
    
    # Check 3: Configuration validation
    console.print()
    console.print(f"[bold]Checking configuration...[/]")
    
    config_issues: list[str] = []
    
    if not settings.verifier_url:
        config_issues.append("Verifier URL is not set")
    elif not settings.verifier_url.startswith(("http://", "https://")):
        config_issues.append("Verifier URL must start with http:// or https://")
    
    if not settings.network:
        config_issues.append("Network is not set")
    
    if settings.netuid <= 0:
        config_issues.append(f"Invalid netuid: {settings.netuid}")
    
    if config_issues:
        console.print(f"[bold yellow]⚠ Configuration issues found[/]:")
        for issue in config_issues:
            console.print(f"  • {issue}")
        checks_warning += 1
        config_status = "Issues found"
    else:
        console.print("[bold green]✓ Configuration is valid[/]")
        checks_passed += 1
        config_status = "Valid"
    
    results.append({
        "name": "Configuration",
        "status": "pass" if not config_issues else "warning",
        "details": config_status,
        "issues": config_issues if config_issues else None,
    })
    
    # Summary
    console.print()
    console.print("[bold cyan]━━━ Summary ━━━[/]")
    
    summary_table = Table(show_header=True, header_style="bold cyan")
    summary_table.add_column("Check", style="cyan")
    summary_table.add_column("Status", justify="center")
    summary_table.add_column("Details", style="dim")
    summary_table.add_column("Latency", justify="right", style="dim")
    
    for result in results:
        status_icon = {
            "pass": "[bold green]✓[/]",
            "warning": "[bold yellow]⚠[/]",
            "fail": "[bold red]✗[/]",
        }.get(result["status"], "?")
        
        latency_str = f"{result['latency_ms']}ms" if result.get("latency_ms") else "-"
        details = result["details"]
        if result.get("issues"):
            details += f" ({len(result['issues'])} issue(s))"
        
        summary_table.add_row(
            result["name"],
            status_icon,
            details,
            latency_str,
        )
    
    console.print(summary_table)
    console.print()
    
    # Overall status
    total_checks = checks_passed + checks_failed + checks_warning
    if checks_failed == 0 and checks_warning == 0:
        console.print("[bold green]✓ All checks passed![/] CLI is ready to use.")
        raise typer.Exit(code=0)
    elif checks_failed == 0:
        console.print(
            f"[bold yellow]⚠ {checks_warning} warning(s) found[/], but CLI should work. "
            "Review configuration if needed."
        )
        raise typer.Exit(code=0)
    else:
        console.print(
            f"[bold red]✗ {checks_failed} check(s) failed[/], {checks_warning} warning(s). "
            "Please fix issues before using the CLI."
        )
        if verbose:
            console.print("\n[bold]Troubleshooting:[/]")
            console.print("• Check your network connectivity")
            console.print(f"• Verify verifier URL: {settings.verifier_url}")
            console.print(f"• Verify Bittensor network: {settings.network}")
            console.print("• Check environment variables: CARTHA_VERIFIER_URL, CARTHA_NETWORK, CARTHA_NETUID")
        raise typer.Exit(code=1)

