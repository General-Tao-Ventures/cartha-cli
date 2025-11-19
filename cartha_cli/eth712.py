"""Helpers for building Cartha EIP-712 payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

try:
    # Use new API if available
    from eth_account.messages import encode_typed_data
except ImportError:
    # Fallback for older versions of eth_account
    from eth_account.messages import encode_structured_data as encode_typed_data
from hexbytes import HexBytes


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

    def to_eip712(self) -> Dict[str, Any]:
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
            ]
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
        return {"domain": domain, "types": types, "primaryType": "LockProof", "message": message}

    def encode(self) -> bytes:
        return encode_typed_data(self.to_eip712())


__all__ = ["LockProofMessage"]
