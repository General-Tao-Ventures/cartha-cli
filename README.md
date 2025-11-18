# Cartha CLI

Miner-facing command line tool for the Cartha subnet. The CLI wraps Bittensor wallet operations,
subnet registration, verifier interactions, and signature helpers so miners can prove hotkey
ownership and submit LockProofs without touching raw cryptography.

## Requirements

- Python 3.11
- [`uv`](https://github.com/astral-sh/uv) or `pip` for dependency management

## Quick Start

```bash
uv sync              # install dependencies into .venv
uv run cartha        # show CLI help
```

Run tests with `uv run pytest` or `make test` once the task list is implemented.

## Environment

Set the following environment variables before invoking commands that reach the verifier:

| Variable | Description |
| --- | --- |
| `CARTHA_NETWORK` / `CARTHA_NETUID` | Bittensor network + subnet netuid. Defaults: `finney`/`35`. |
| `CARTHA_VERIFIER_URL` | Verifier endpoint URL (default `http://127.0.0.1:8000`). |

Wallet files must already exist under the Bittensor wallet path (or be available via `BITTENSOR_WALLET_PATH`).

## Ownership Challenge Flow

Commands that expose sensitive information (`cartha pair status`, the post-registration password fetch)
perform a local challenge/response handshake:

1. The CLI loads your wallet (`--wallet-name`, `--wallet-hotkey`) and confirms it owns the supplied hotkey.
2. A challenge string is generated:

  ```json
   cartha-pair-auth|network:{network}|netuid:{netuid}|slot:{slot}|hotkey:{hotkey}|ts:{unix_ts}
  ```

3.The hotkey signs the challenge via `wallet.hotkey.sign(...)` and the CLI verifies the signature locally.
4. The signed payload plus bearer token is POSTed to the verifier (`/v1/pair/status` or `/v1/pair/password/retrieve`).
5. The challenge expires 120 seconds after issuance; the CLI prints the expiry timestamp.

If the wallet is locked or the hotkey/UID do not match the on-chain metagraph, the CLI exits with guidance.

## Key Commands

```bash
# Register a hotkey via burned registration and print UID + pair password
cartha register \
  --wallet-name cold --wallet-hotkey hot \
  --network finney --netuid 35

# Query pair status once registered (requires unlocked wallet)
cartha pair status \
  --wallet-name cold --wallet-hotkey hot \
  --hotkey bt1... --slot 123

# Submit a previously signed LockProof payload
cartha prove-lock \
  --chain 8453 \
  --vault 0xVAULT \
  --tx 0xLOCKTX \
  --amount 250000000000 \
  --hotkey bt1... \
  --slot 123 \
  --miner-evm 0xEVMADDR \
  --pwd 0xPAIRPWD \
  --signature 0xEIP712SIG
```

`cartha claim-deposit` is an alias of `prove-lock` for deposit-first workflows. The CLI no longer holds
the EVM private key; miners sign the EIP‑712 payload externally (hardware wallet, ethers, etc.) and supply
the resulting signature alongside the password.
