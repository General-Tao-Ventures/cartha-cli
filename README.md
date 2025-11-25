# Cartha CLI

**The official command-line tool for Cartha subnet miners.** A simple, powerful way to manage your mining operations—from registration to tracking your locked funds.

## Why Cartha CLI?

Cartha CLI makes mining on the Cartha subnet effortless:

- **🔐 One-Click Registration** - Get started mining in minutes
- **📊 Instant Status Updates** - See all your pools, balances, and expiration dates at a glance
- **⏰ Smart Expiration Warnings** - Never miss a renewal with color-coded countdowns
- **💼 Multi-Pool Management** - Track multiple trading pairs in one place
- **🔑 Secure by Default** - Your password stays hidden until you actually need it

## Quick Start

```bash
# Install dependencies
uv sync

# Show available commands
uv run cartha

# Get started with registration
uv run cartha miner register --help

# Check your miner status (no authentication needed)
uv run cartha miner status --help

# Or use short aliases
uv run cartha m status
uv run cartha v lock
```

## Requirements

- Python 3.11
- Bittensor wallet
- [`uv`](https://github.com/astral-sh/uv) package manager (or pip)

## What You Can Do

### Get Started

**Register your miner:**
```bash
cartha miner register --wallet-name your-wallet --wallet-hotkey your-hotkey
```

**Check your status anytime:**
```bash
cartha miner status --wallet-name your-wallet --wallet-hotkey your-hotkey
# Or use the short alias: cartha m status
```

### Track Your Pools

See all your active trading pairs, balances, and when they expire—all in one command. The CLI shows you:
- Which pools are active and earning rewards
- How much you have locked in each pool
- Days remaining before expiration (with helpful warnings)
- Which pools are included in the next reward epoch

### Lock Your Funds

After depositing USDC to a vault, lock it with:
```bash
cartha vault lock --payload-file your-lock-proof.json
# Or use: cartha v lock
```

### View Your Password

When you need your password (like for signing transactions):
```bash
cartha miner password --wallet-name your-wallet --wallet-hotkey your-hotkey
```

**Tip:** Use `miner status` for daily checks—it's faster and doesn't require signing. Only use `miner password` when you actually need it.

## Need Help?

- **[Full Command Reference](docs/COMMANDS.md)** - Complete guide to all commands
- **[Testnet Guide](testnet/README.md)** - Getting started on testnet
- **[Feedback & Support](docs/FEEDBACK.md)** - Questions or suggestions?

## Contributing

We welcome contributions! Please see our [Feedback & Support](docs/FEEDBACK.md) page for ways to get involved.

---

**Made with ❤ by GTV**
