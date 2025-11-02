# Cartha CLI

Miner-facing command line tool for the Cartha subnet. The CLI wraps Bittensor wallet operations,
subnet registration, verifier interactions, and signature helpers using Fiber so miners can prove
hotkey ownership and submit LockProofs without touching raw cryptography.

## Requirements

- Python 3.11
- [`uv`](https://github.com/astral-sh/uv) or `pip` for dependency management

## Quick Start

```bash
uv sync              # install dependencies into .venv
uv run cartha         # show CLI help
```

Run tests with `uv run pytest` or `make test` once the task list is implemented.
