"""Vault address mapping based on pool_id (1:1 relationship)."""

from __future__ import annotations

# Vault-Pool Mapping (1:1 relationship)
# Each pool has its own dedicated vault address to prevent cross-book risk
VAULT_POOL_MAPPING: dict[str, str] = {
    # MVP pools
    "EURUSD": "0x00000000000000000000000000000000000000AA",
    "GBPUSD": "0x00000000000000000000000000000000000000BB",
    "USDJPY": "0x00000000000000000000000000000000000000CC",
    "BTCUSDC": "0x00000000000000000000000000000000000000DD",
    "XAUUSDC": "0x00000000000000000000000000000000000000EE",
    "ETHUSDC": "0x00000000000000000000000000000000000000FF",
    # Legacy pools mapped to MVP equivalents
    "USDEUR": "0x00000000000000000000000000000000000000AA",  # -> EURUSD vault
    "XAUUSD": "0x00000000000000000000000000000000000000EE",  # -> XAUUSDC vault
    "BTCUSD": "0x00000000000000000000000000000000000000DD",  # -> BTCUSDC vault
    "ETHUSD": "0x00000000000000000000000000000000000000FF",  # -> ETHUSDC vault
    "JPYUSD": "0x00000000000000000000000000000000000000CC",  # -> USDJPY vault
}

# Reverse mapping: pool_id (hex) -> vault address
# This is populated from pool_ids.py mappings
POOL_ID_TO_VAULT: dict[str, str] = {}


def _build_pool_id_to_vault_mapping() -> None:
    """Build reverse mapping from pool_id (hex) to vault address."""
    try:
        from .pool_ids import POOL_MAPPINGS
        
        for pool_name, pool_id_hex in POOL_MAPPINGS.items():
            vault = VAULT_POOL_MAPPING.get(pool_name.upper())
            if vault:
                POOL_ID_TO_VAULT[pool_id_hex.lower()] = vault.lower()
    except ImportError:
        # Fallback if pool_ids not available
        pass


# Initialize the reverse mapping
_build_pool_id_to_vault_mapping()


def get_vault_for_pool(pool_id: str | None) -> str:
    """Get vault address for a given pool_id.
    
    Args:
        pool_id: Pool ID (hex string) or pool name (readable name)
        
    Returns:
        Vault address (checksummed)
        
    Examples:
        >>> get_vault_for_pool("EURUSD")
        '0x00000000000000000000000000000000000000AA'
        >>> get_vault_for_pool("0x0000000000000000000000000000000000000000000000000000000000455552555344")
        '0x00000000000000000000000000000000000000AA'
    """
    if not pool_id:
        # Default to EURUSD vault
        return "0x00000000000000000000000000000000000000AA"
    
    pool_id_lower = pool_id.lower().strip()
    
    # Check if it's a readable name first
    pool_name_upper = pool_id.upper().strip()
    if pool_name_upper in VAULT_POOL_MAPPING:
        return VAULT_POOL_MAPPING[pool_name_upper]
    
    # Check if it's a hex pool_id
    if pool_id_lower in POOL_ID_TO_VAULT:
        return POOL_ID_TO_VAULT[pool_id_lower]
    
    # Try to normalize hex string
    if pool_id_lower.startswith("0x"):
        normalized = pool_id_lower
    else:
        normalized = "0x" + pool_id_lower
    
    if normalized in POOL_ID_TO_VAULT:
        return POOL_ID_TO_VAULT[normalized]
    
    # Fallback to default vault (EURUSD)
    return "0x00000000000000000000000000000000000000AA"


def get_pool_name_for_vault(vault_address: str) -> str | None:
    """Get pool name for a given vault address.
    
    Args:
        vault_address: Vault address (checksummed or lowercase)
        
    Returns:
        Pool name if found, None otherwise
    """
    vault_lower = vault_address.lower()
    for pool_name, vault in VAULT_POOL_MAPPING.items():
        if vault.lower() == vault_lower:
            return pool_name
    return None

