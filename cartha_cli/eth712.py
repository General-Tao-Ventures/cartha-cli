"""Helpers for building Cartha EIP-712 payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from eth_account.messages import encode_structured_data
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
        }
        return {"domain": domain, "types": types, "primaryType": "LockProof", "message": message}

    def encode(self) -> bytes:
        return encode_structured_data(self.to_eip712())


__all__ = ["LockProofMessage"]
