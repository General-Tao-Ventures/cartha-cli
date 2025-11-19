"""Helpers for building Cartha EIP-712 payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    # Try to import new API first
    from eth_account.messages import encode_typed_data as _encode_typed_data_new

    _has_new_api = True
except ImportError:
    _has_new_api = False

try:
    # Also try to import old API as fallback
    from eth_account.messages import (
        encode_structured_data as _encode_structured_data_old,
    )

    _has_old_api = True
except ImportError:
    _has_old_api = False

if not _has_new_api and not _has_old_api:
    raise ImportError(
        "Neither encode_typed_data nor encode_structured_data is available. Install eth-account."
    )

from hexbytes import HexBytes


def _convert_hexbytes_to_bytes(typed_data: dict) -> dict:
    """Convert HexBytes to bytes in message."""
    if "message" in typed_data:
        message = dict(typed_data["message"])
        for key, value in message.items():
            if isinstance(value, HexBytes):
                message[key] = bytes(value)
        typed_data["message"] = message
    return typed_data


def _convert_hexbytes_to_hex_no_prefix(typed_data: dict) -> dict:
    """Convert HexBytes to hex strings without 0x prefix."""
    if "message" in typed_data:
        message = dict(typed_data["message"])
        for key, value in message.items():
            if isinstance(value, HexBytes):
                hex_str = value.hex()
                # Remove 0x prefix if present
                if hex_str.startswith("0x"):
                    hex_str = hex_str[2:]
                message[key] = hex_str
        typed_data["message"] = message
    return typed_data


def _convert_hexbytes_to_hex_string(typed_data: dict) -> dict:
    """Convert HexBytes to hex strings with 0x prefix."""
    if "message" in typed_data:
        message = dict(typed_data["message"])
        for key, value in message.items():
            if isinstance(value, HexBytes):
                message[key] = value.hex()
        typed_data["message"] = message
    return typed_data


def _encode_typed_data_compat(typed_data: dict) -> bytes:
    """Wrapper to handle API differences between encode_typed_data and encode_structured_data.

    Tries both APIs with different HexBytes conversion formats.
    """
    import copy

    # Try different formats for HexBytes conversion
    conversion_formats = [
        # Format 1: Keep HexBytes as-is (new API and some old API versions accept this)
        ("as-is", lambda td: td),
        # Format 2: Convert HexBytes to bytes (old API often needs this)
        ("bytes", _convert_hexbytes_to_bytes),
        # Format 3: Convert HexBytes to hex strings without 0x prefix
        ("hex-no-prefix", _convert_hexbytes_to_hex_no_prefix),
        # Format 4: Convert HexBytes to hex strings with 0x prefix
        ("hex-with-prefix", _convert_hexbytes_to_hex_string),
    ]

    errors = []

    # Try new API first with each format
    if _has_new_api:
        for format_name, convert_fn in conversion_formats:
            try:
                typed_data_converted = convert_fn(copy.deepcopy(typed_data))
                return _encode_typed_data_new(typed_data_converted)
            except Exception as e:
                errors.append(f"New API ({format_name}): {e}")
                continue

    # Try old API with each format
    if _has_old_api:
        for format_name, convert_fn in conversion_formats:
            try:
                typed_data_converted = convert_fn(copy.deepcopy(typed_data))
                return _encode_structured_data_old(primitive=typed_data_converted)
            except Exception as e:
                errors.append(f"Old API ({format_name}): {e}")
                continue

    # If all attempts failed, raise comprehensive error
    error_summary = "\n".join(f"  - {err}" for err in errors)
    raise RuntimeError(
        f"EIP-712 encoding failed with all APIs and formats:\n{error_summary}"
    )


@dataclass
class LockProofMessage:
    chain_id: int
    vault_address: str
    miner_evm_address: str
    miner_hotkey: str
    slot_uid: str
    tx_hash: str
    amount: int
    password: str
    timestamp: int

    def to_eip712(self) -> dict[str, Any]:
        domain = {
            "name": "CarthaLockProof",
            "version": "1",
            "chainId": self.chain_id,
        }
        types = {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "LockProof": [
                {"name": "vaultAddress", "type": "address"},
                {"name": "minerEvmAddress", "type": "address"},
                {"name": "minerHotkey", "type": "string"},
                {"name": "slotUID", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "txHash", "type": "bytes32"},
                {"name": "amount", "type": "uint256"},
                {"name": "pwd", "type": "bytes32"},
                {"name": "timestamp", "type": "uint256"},
            ],
        }
        message = {
            "vaultAddress": self.vault_address,
            "minerEvmAddress": self.miner_evm_address,
            "minerHotkey": self.miner_hotkey,
            "slotUID": self.slot_uid,
            "chainId": self.chain_id,
            "txHash": HexBytes(self.tx_hash),
            "amount": self.amount,
            "pwd": HexBytes(self.password),
            "timestamp": self.timestamp,
        }
        return {
            "domain": domain,
            "types": types,
            "primaryType": "LockProof",
            "message": message,
        }

    def encode(self) -> bytes:
        return _encode_typed_data_compat(self.to_eip712())


__all__ = ["LockProofMessage"]
