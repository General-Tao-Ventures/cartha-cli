# Cartha CLI

Typer-based command line interface for Cartha miners and operators.

## Setup

```bash
# Install dependencies
uv sync

# Run CLI (example)
uv run cartha --help
```

Configure backend URLs and keys via environment variables (e.g. `CARTHA_VERIFIER_URL`,
`CARTHA_EVM_PRIVATE_KEY`) when running commands like `pair-status` or `prove-lock`.
