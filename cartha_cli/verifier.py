"""HTTP helpers for interacting with the Cartha verifier service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

import requests

from .config import settings


class VerifierError(RuntimeError):
    """Raised when the verifier cannot be reached or returns an error."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class PairStatus:
    state: str
    has_pwd: bool
    issued_at: str | None


def _build_url(path: str) -> str:
    base = settings.verifier_url.rstrip("/")
    return f"{base}{path}"


def _request(
    method: str,
    path: str,
    *,
    params: Dict[str, Any] | None = None,
    json_data: Dict[str, Any] | None = None,
    require_cli_token: bool = False,
) -> Dict[str, Any]:
    headers: Dict[str, str] = {"Accept": "application/json"}
    if require_cli_token:
        token = settings.verifier_cli_token
        if not token:
            raise VerifierError("Verifier CLI token missing. Set CARTHA_VERIFIER_CLI_TOKEN.")
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.request(
            method,
            _build_url(path),
            params=params,
            json=json_data,
            headers=headers,
            timeout=10,
        )
    except requests.RequestException as exc:  # pragma: no cover - network failure
        raise VerifierError(f"Failed to reach verifier: {exc}") from exc

    try:
        data = response.json()
    except ValueError:
        data = None

    if response.status_code >= 400:
        if isinstance(data, dict):
            detail = data.get("detail") or data.get("error") or response.text
        else:
            detail = response.text or "Unknown verifier error"
        raise VerifierError(detail.strip(), status_code=response.status_code)

    if not isinstance(data, dict):
        raise VerifierError("Unexpected verifier response payload.")
    return data


def fetch_pair_status(hotkey: str, slot: str) -> Dict[str, Any]:
    """Return the status for a (hotkey, slotUID) pair."""
    return _request(
        "GET",
        "/v1/pair/status",
        params={"hotkey": hotkey, "slot": slot},
    )


def fetch_pair_password(hotkey: str, slot: str) -> Dict[str, Any]:
    """Fetch the pair password via the secured endpoint."""
    return _request(
        "GET",
        "/v1/pair/password",
        params={"hotkey": hotkey, "slot": slot},
        require_cli_token=True,
    )


def submit_lock_proof(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Submit a lock proof to the verifier."""
    return _request(
        "POST",
        "/v1/proofs/lock",
        json_data=payload,
    )


__all__ = ["VerifierError", "fetch_pair_status", "fetch_pair_password", "submit_lock_proof"]
