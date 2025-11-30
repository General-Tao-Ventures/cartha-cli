"""Helper functions for generating and displaying human-readable pool IDs.

Pool IDs are bytes32 (32 bytes = 64 hex chars), so we can encode readable text
in hex format. This module provides helpers to convert between readable names
and hex pool IDs.
"""

from __future__ import annotations

# Predefined pool mappings (readable name -> hex pool ID)
# MVP pairs from architecture: EUR/USD, GBP/USD, USD/JPY, BTC/USDC, XAU/USDC, ETH/USDC
# Pool IDs are bytes32 (32 bytes = 64 hex chars), right-padded (data at end, zeros at beginning)
POOL_MAPPINGS: dict[str, str] = {
    "EURUSD": "0x0000000000000000000000000000000000000000000000000000455552555344",  # EUR/USD
    "GBPUSD": "0x0000000000000000000000000000000000000000000000000000474250555344",  # GBP/USD
    "USDJPY": "0x00000000000000000000000000000000000000000000000000005553444a5059",  # USD/JPY
    "BTCUSDC": "0x0000000000000000000000000000000000000000000000000042544355534443",  # BTC/USDC
    "XAUUSDC": "0x0000000000000000000000000000000000000000000000000058415555534443",  # XAU/USDC
    "ETHUSDC": "0x0000000000000000000000000000000000000000000000000045544855534443",  # ETH/USDC
    # Legacy mappings for backward compatibility (if needed)
    "USDEUR": "0x0000000000000000000000000000000000000000000000000000555344455552",  # Legacy: USD/EUR
    "XAUUSD": "0x0000000000000000000000000000000000000000000000000000584155555344",  # Legacy: XAU/USD
    "BTCUSD": "0x0000000000000000000000000000000000000000000000000000425443555344",  # Legacy: BTC/USD
    "ETHUSD": "0x0000000000000000000000000000000000000000000000000000455448555344",  # Legacy: ETH/USD
    "JPYUSD": "0x00000000000000000000000000000000000000000000000000004a5059555344",  # Legacy: JPY/USD
}

# Reverse mapping (hex -> readable name)
POOL_NAMES: dict[str, str] = {v.lower(): k for k, v in POOL_MAPPINGS.items()}


def pool_name_to_id(pool_name: str) -> str:
    """Convert a readable pool name to hex pool ID.
    
    Args:
        pool_name: Readable name (e.g., "USDEUR", "XAUUSD")
        
    Returns:
        Hex pool ID (bytes32 format)
        
    Examples:
        >>> pool_name_to_id("USDEUR")
        '0x0000000000000000000000000000000000000000000000000000000000555344455552'
    """
    pool_name_upper = pool_name.upper()
    if pool_name_upper in POOL_MAPPINGS:
        return POOL_MAPPINGS[pool_name_upper]
    
    # If not in predefined mappings, encode the name as hex
    # Pad to 32 bytes (64 hex chars), right-padded (data at end, zeros at beginning)
    name_bytes = pool_name.encode("utf-8")
    if len(name_bytes) > 32:
        raise ValueError(f"Pool name too long: {pool_name} (max 32 bytes)")
    
    # Right-pad with zeros to 32 bytes (data at end, zeros at beginning)
    padded = name_bytes.rjust(32, b"\x00")
    hex_id = "0x" + padded.hex()
    # Validate length
    if len(hex_id) != 66:  # 0x + 64 hex chars
        raise ValueError(f"Generated pool_id has incorrect length: {len(hex_id)} (expected 66)")
    return hex_id


def pool_id_to_name(pool_id: str) -> str | None:
    """Convert a hex pool ID to readable name if available.
    
    Args:
        pool_id: Hex pool ID (bytes32 format)
        
    Returns:
        Readable name if found, None otherwise
        
    Examples:
        >>> pool_id_to_name("0x0000000000000000000000000000000000000000000000000000000000555344455552")
        'USDEUR'
    """
    pool_id_lower = pool_id.lower()
    if pool_id_lower in POOL_NAMES:
        return POOL_NAMES[pool_id_lower]
    
    # Try to decode from hex
    try:
        # Remove 0x prefix
        hex_str = pool_id_lower.removeprefix("0x")
        # Convert to bytes
        pool_bytes = bytes.fromhex(hex_str)
        # Try to decode as UTF-8 (remove trailing zeros)
        name = pool_bytes.rstrip(b"\x00").decode("utf-8", errors="ignore")
        if name and name.isprintable():
            return name
    except Exception:
        pass
    
    return None


def format_pool_id(pool_id: str) -> str:
    """Format a pool ID for display (shows readable name if available).
    
    Args:
        pool_id: Hex pool ID
        
    Returns:
        Formatted string: "USDEUR (0x...)" or just "0x..." if no name found
    """
    name = pool_id_to_name(pool_id)
    if name:
        return f"{name} ({pool_id})"
    return pool_id


def list_pools() -> dict[str, str]:
    """List all predefined pools.
    
    Returns:
        Dictionary mapping readable names to hex pool IDs
    """
    return POOL_MAPPINGS.copy()

