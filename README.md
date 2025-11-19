# Cartha CLI

**The official command-line interface for Cartha subnet miners.** Streamline your mining operations with a powerful, user-friendly CLI that handles hotkey registration, pair password management, and lock proof submissions—all without touching raw cryptography.

## Why Cartha CLI?

Cartha CLI simplifies the entire miner workflow on the Cartha subnet:

- **🔐 Secure Registration** - Register your hotkey on the Cartha subnet with burned TAO registration
- **🔑 Password Management** - Automatically generate and manage pair passwords for verifier authentication
- **💼 Lock Proof Submission** - Submit EIP-712 signed lock proofs for your USDC deposits with ease
- **🛡️ Built-in Security** - Local challenge/response authentication ensures only you can access sensitive operations
- **⚡ Interactive Workflows** - Smart prompts guide you through each step, with support for both local and external wallet signing

## Quick Start

```bash
# Install dependencies
uv sync

# Show available commands
uv run cartha

# Get started with registration
uv run cartha register --help
```

## Requirements

- Python 3.11
- [`uv`](https://github.com/astral-sh/uv) for dependency management
- Bittensor and Bittensor wallets

## Commands Overview

### `cartha register`

Register your hotkey on the Cartha subnet and obtain your pair password. This command handles the entire registration process, including burned TAO registration and automatic pair password generation from the verifier. The pair password is essential for all subsequent verifier interactions.

### `cartha pair status`

Check the status of your miner pair on the Cartha Network. This command signs a challenge message with your hotkey to prove ownership, then retrieves pair metadata including verification status, lock amounts, and password issuance timestamps.

### `cartha prove-lock`

The happy path. Submit a lock proof for your USDC deposit to the verifier. This command handles the entire EIP-712 signing workflow, supporting both local signing (with your EVM private key) and external signing (MetaMask, hardware wallets, etc.).

### `cartha claim-deposit` - *`Not Recommended!`*

An alias for `prove-lock` designed for deposit-first workflows. Use this command if you've already made your USDC deposit and want to claim it by submitting a lock proof.

### `cartha version`

Display the CLI version information.

## Documentation

- **[Command Reference](docs/COMMANDS.md)** - Detailed documentation for all commands and their arguments
- **[EIP-712 Signing Guide](docs/EIP712_SIGNING.md)** - Complete guide for signing lock proofs
- **[Testnet Guide](testnet/README.md)** - Testnet-specific instructions and demo scripts
- **[Feedback & Support](docs/FEEDBACK.md)** - Get help and provide feedback

## Contributing

We welcome contributions! Please see our [Feedback & Support](docs/FEEDBACK.md) page for ways to get involved.

---

**Made with ❤ by GTV**
