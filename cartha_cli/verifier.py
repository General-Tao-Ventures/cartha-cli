"""HTTP helpers for interacting with the Cartha verifier service."""

from __future__ import annotations

from typing import Any

import requests  # type: ignore[import-untyped]

from .config import settings


class VerifierError(RuntimeError):
    """Raised when the verifier cannot be reached or returns an error."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _build_url(path: str) -> str:
    base = settings.verifier_url.rstrip("/")
    return f"{base}{path}"


def _request(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    headers: dict[str, str] = {"Accept": "application/json"}
    url = _build_url(path)

    try:
        response = requests.request(
            method,
            url,
            params=params,
            json=json_data,
            headers=headers,
            timeout=30,  # Increased from 10s to handle slow database queries and network latency
        )
    except requests.RequestException as exc:  # pragma: no cover - network failure
        # Provide more context about the failed URL
        error_msg = f"Failed to reach verifier at {url}: {exc}"
        raise VerifierError(error_msg) from exc

    try:
        data = response.json()
    except ValueError:
        data = None

    if response.status_code >= 400:
        if isinstance(data, dict):
            detail = data.get("detail") or data.get("error") or response.text
        else:
            detail = response.text or "Unknown verifier error"

        # Handle FastAPI validation errors which return detail as a list
        if isinstance(detail, list):
            # Format list of validation errors into a readable string
            formatted_errors = []
            for item in detail:
                if isinstance(item, dict):
                    # Extract field location and message
                    loc = item.get("loc", [])
                    msg = item.get("msg", "Validation error")
                    field = " -> ".join(str(x) for x in loc) if loc else "unknown"
                    formatted_errors.append(f"{field}: {msg}")
                else:
                    formatted_errors.append(str(item))
            detail = "; ".join(formatted_errors)
        elif isinstance(detail, str):
            detail = detail.strip()
        else:
            detail = str(detail)

        # Log error details for debugging (only in debug mode or for 500 errors)
        if response.status_code >= 500:
            import logging

            logger = logging.getLogger(__name__)
            logger.debug(f"Verifier error - URL: {url}")
            logger.debug(f"Verifier error - Status: {response.status_code}")
            logger.debug(f"Verifier error - Response: {response.text[:500]}")

        raise VerifierError(detail, status_code=response.status_code)

    if not isinstance(data, dict):
        raise VerifierError("Unexpected verifier response payload.")
    return data


def fetch_pair_status(
    *,
    hotkey: str,
    slot: str,
    network: str,
    netuid: int,
    message: str,
    signature: str,
) -> dict[str, Any]:
    """Return the status for a (hotkey, slotUID) pair after verifying ownership."""
    payload = {
        "hotkey": hotkey,
        "slot": slot,
        "network": network,
        "netuid": netuid,
        "message": message,
        "signature": signature,
    }
    return _request(
        "POST",
        "/v1/pair/status",
        json_data=payload,
    )


def fetch_pair_password(
    *,
    hotkey: str,
    slot: str,
    network: str,
    netuid: int,
    message: str,
    signature: str,
) -> dict[str, Any]:
    """Fetch the pair password via the secured endpoint."""
    payload = {
        "hotkey": hotkey,
        "slot": slot,
        "network": network,
        "netuid": netuid,
        "message": message,
        "signature": signature,
    }
    return _request(
        "POST",
        "/v1/pair/password/retrieve",
        json_data=payload,
    )


def register_pair_password(
    *,
    hotkey: str,
    slot: str,
    network: str,
    netuid: int,
    message: str,
    signature: str,
) -> dict[str, Any]:
    payload = {
        "hotkey": hotkey,
        "slot": slot,
        "network": network,
        "netuid": netuid,
        "message": message,
        "signature": signature,
    }
    return _request(
        "POST",
        "/v1/pair/password/register",
        json_data=payload,
    )


def submit_lock_proof(payload: dict[str, Any]) -> dict[str, Any]:
    """Submit a lock proof to the verifier."""
    return _request(
        "POST",
        "/v1/proofs/lock",
        json_data=payload,
    )


__all__ = [
    "VerifierError",
    "fetch_pair_status",
    "fetch_pair_password",
    "register_pair_password",
    "submit_lock_proof",
]
