"""Utility functions for the Cartha CLI."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from decimal import ROUND_DOWN, Decimal, InvalidOperation
from zoneinfo import ZoneInfo

import typer
from rich import box
from rich.table import Table

from .config import settings

console = typer.get_current().console if hasattr(typer, "get_current") else None


def normalize_hex(value: str, prefix: str = "0x") -> str:
    """Normalize hex string to ensure it has the correct prefix."""
    value = value.strip()
    if not value.startswith(prefix):
        value = prefix + value
    return value


def format_timestamp(ts: int | float | str | None) -> str:
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


def usdc_to_base_units(value: str) -> int:
    """Convert USDC amount string to base units (micro-USDC).

    Args:
        value: USDC amount as string (e.g., "250.5")

    Returns:
        Amount in base units (e.g., 250500000)

    Raises:
        typer.Exit: If value is invalid or non-positive
    """
    try:
        decimal_value = Decimal(value.strip())
    except (InvalidOperation, AttributeError) as exc:
        raise typer.Exit(code=1) from exc
    if decimal_value <= 0:
        raise typer.Exit(code=1)
    quantized = decimal_value.quantize(Decimal("0.000001"), rounding=ROUND_DOWN)
    return int(quantized * Decimal(10**6))


def get_current_epoch_start(reference: datetime | None = None) -> datetime:
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


def get_next_epoch_freeze_time(reference: datetime | None = None) -> datetime:
    """Calculate the next epoch freeze time (next Friday 00:00 UTC).

    Args:
        reference: Reference datetime (defaults to now in UTC)

    Returns:
        Datetime of the next epoch freeze (next Friday 00:00 UTC)
    """
    current_start = get_current_epoch_start(reference)
    # If we're exactly at epoch start, next is in 7 days
    # Otherwise, next is current + 7 days
    return current_start + timedelta(days=7)


def format_countdown(seconds: float) -> str:
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


def get_local_timezone() -> ZoneInfo:
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

