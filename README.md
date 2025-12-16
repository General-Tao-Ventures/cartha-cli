# Cartha CLI

**The official command-line tool for Cartha subnet miners.** Cartha is the Liquidity Provider for 0xMarkets DEX. A simple, powerful way to manage your mining operations—from registration to tracking your locked funds.

## Why Cartha CLI?

Cartha CLI makes mining on the Cartha subnet effortless. As the Liquidity Provider for 0xMarkets DEX, Cartha enables miners to provide liquidity and earn rewards:

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

# Check CLI health and connectivity
uv run cartha health

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

### View Available Pools

See all available pools with their pool IDs and vault addresses:

```bash
cartha vault pools
# Or use: cartha v pools
```

This shows you which pools are available, their full pool IDs, vault contract addresses, and chain IDs.

### Lock Your Funds

Create a new lock position with the streamlined lock flow:
```bash
cartha vault lock \
  --coldkey your-wallet \
  --hotkey your-hotkey \
  --pool-id "BTCUSD" \
  --amount 1000.0 \
  --lock-days 30 \
  --owner-evm 0xYourEVMAddress \
  --chain 8453 \
  --vault-address 0xVaultAddress
# Or use: cartha v lock
```

**Parameter Notes:**
- `--owner` and `--owner-evm` are interchangeable (EVM address that will own the lock)
- `--vault` and `--vault-address` are interchangeable (vault contract address)
- `--network` accepts `test` (netuid 78) or `finney` (netuid 35, default)
- `--chain` or `--chain-id` are interchangeable (EVM chain ID: 84532 for Base Sepolia testnet)

The CLI will:
1. Check your registration on the specified network (subnet 35 for finney, subnet 78 for test)
2. Authenticate with your Bittensor hotkey
3. Request a signed LockRequest from the verifier
4. Automatically open the Cartha Lock UI in your browser with all parameters pre-filled
5. Guide you through Phase 1 (Approve USDC) and Phase 2 (Lock Position) via the web interface
6. Automatically detect when approval completes and proceed to Phase 2
7. The verifier automatically detects your lock and adds you to the upcoming epoch

**Managing Positions**: Visit https://cartha.finance/manage to view all your positions, extend locks, or top up existing positions.

### View Your Password

When you need your password (like for signing transactions):
```bash
cartha miner password --wallet-name your-wallet --wallet-hotkey your-hotkey
```

**Tip:** Use `miner status` for daily checks—it's faster and doesn't require signing. Only use `miner password` when you actually need it.

### Check Your Setup

Verify your CLI is configured correctly and can reach all services:

```bash
cartha health
```

This checks:
- Verifier connectivity and latency
- Bittensor network connectivity
- Configuration validation

Use `cartha health --verbose` for detailed troubleshooting information.

## Need Help?

- **[Full Command Reference](docs/COMMANDS.md)** - Complete guide to all commands
- **[Testnet Guide](testnet/README.md)** - Getting started on testnet
- **[Feedback & Support](docs/FEEDBACK.md)** - Questions or suggestions?

## Contributing

We welcome contributions! Please see our [Feedback & Support](docs/FEEDBACK.md) page for ways to get involved.

---

**Made with ❤ by GTV**
