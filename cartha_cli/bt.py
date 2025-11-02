"""Bittensor convenience wrappers."""

from __future__ import annotations

import bittensor as bt


def get_subtensor(network: str) -> bt.Subtensor:
    return bt.subtensor(network=network)


def get_wallet(name: str, hotkey: str) -> bt.wallet:
    return bt.wallet(name=name, hotkey=hotkey)


__all__ = ["get_subtensor", "get_wallet"]
