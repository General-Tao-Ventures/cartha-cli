"""Bittensor convenience wrappers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

try:
    import bittensor as bt
except ImportError:  # pragma: no cover - surfaced at call time
    bt = None


def get_subtensor(network: str) -> bt.Subtensor:
    if bt is None:  # pragma: no cover - safeguarded for tests
        raise RuntimeError("bittensor is not installed")
    return bt.subtensor(network=network)


def get_wallet(name: str, hotkey: str) -> bt.wallet:
    if bt is None:  # pragma: no cover
        raise RuntimeError("bittensor is not installed")
    return bt.wallet(name=name, hotkey=hotkey)


@dataclass(frozen=True)
class RegistrationResult:
    status: str
    success: bool
    uid: Optional[int]
    hotkey: str
    extrinsic: Optional[str] = None  # Extrinsic hash (e.g., "5759123-5")
    balance_before: Optional[float] = None  # Balance before registration
    balance_after: Optional[float] = None  # Balance after registration


def register_hotkey(
    *,
    network: str,
    wallet_name: str,
    hotkey_name: str,
    netuid: int,
    burned: bool = True,
    cuda: bool = False,
    wait_for_finalization: bool = True,
    wait_for_inclusion: bool = False,
    dev_id: int | list[int] | None = 0,
    tpb: int = 256,
    num_processes: int | None = None,
) -> RegistrationResult:
    """Register a hotkey on the target subnet and return the resulting UID."""

    subtensor = get_subtensor(network)
    wallet = get_wallet(wallet_name, hotkey_name)
    hotkey_ss58 = wallet.hotkey.ss58_address

    if subtensor.is_hotkey_registered(hotkey_ss58, netuid=netuid):
        neuron = subtensor.get_neuron_for_pubkey_and_subnet(hotkey_ss58, netuid)
        uid = None if getattr(neuron, "is_null", False) else getattr(neuron, "uid", None)
        return RegistrationResult(status="already", success=True, uid=uid, hotkey=hotkey_ss58)

    # Get balance before registration
    balance_before = None
    balance_after = None
    extrinsic = None
    
    try:
        balance_obj = subtensor.get_balance(wallet.coldkeypub.ss58_address)
        # Convert Balance object to float using .tao property
        balance_before = balance_obj.tao if hasattr(balance_obj, 'tao') else float(balance_obj)
    except Exception:
        pass  # Balance may not be available, continue anyway

    if burned:
        # burned_register returns (success, block_info) or just success
        registration_result = subtensor.burned_register(
            wallet=wallet,
            netuid=netuid,
            wait_for_finalization=wait_for_finalization,
        )
        
        # Handle both return types: bool or (bool, message)
        if isinstance(registration_result, tuple):
            ok, message = registration_result
            if isinstance(message, str) and message:
                extrinsic = message
        else:
            ok = registration_result
        
        status = "burned"
    else:
        ok = subtensor.register(
            wallet=wallet,
            netuid=netuid,
            wait_for_finalization=wait_for_finalization,
            wait_for_inclusion=wait_for_inclusion,
            cuda=cuda,
            dev_id=dev_id,
            tpb=tpb,
            num_processes=num_processes,
            log_verbose=False,
        )
        status = "pow"
        if isinstance(ok, tuple) and len(ok) == 2:
            ok, message = ok
            if isinstance(message, str):
                extrinsic = message

    if not ok:
        return RegistrationResult(
            status=status, 
            success=False, 
            uid=None, 
            hotkey=hotkey_ss58,
            balance_before=balance_before,
            balance_after=balance_after,
            extrinsic=extrinsic
        )

    # Get balance after registration
    try:
        balance_obj = subtensor.get_balance(wallet.coldkeypub.ss58_address)
        # Convert Balance object to float using .tao property
        balance_after = balance_obj.tao if hasattr(balance_obj, 'tao') else float(balance_obj)
    except Exception:
        pass

    neuron = subtensor.get_neuron_for_pubkey_and_subnet(hotkey_ss58, netuid)
    uid = None if getattr(neuron, "is_null", False) else getattr(neuron, "uid", None)
    
    return RegistrationResult(
        status=status, 
        success=True, 
        uid=uid, 
        hotkey=hotkey_ss58,
        balance_before=balance_before,
        balance_after=balance_after,
        extrinsic=extrinsic
    )


__all__ = ["get_subtensor", "get_wallet", "register_hotkey", "RegistrationResult"]
