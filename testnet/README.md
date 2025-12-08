# Cartha CLI - Testnet Setup Guide

This guide will help you set up and use the Cartha CLI on the public testnet with real vault contracts.

## Prerequisites

- Python 3.11
- [`uv`](https://github.com/astral-sh/uv) package manager (or `pip`)
- Bittensor wallet (for subnet registration)
- Access to the testnet verifier URL
- Testnet TAO (required for subnet registration)
- EVM wallet (MetaMask or similar) with testnet USDC for locking

### Getting Testnet TAO

You'll need testnet TAO to register your hotkey to the subnet. Get testnet TAO from the faucet:

🔗 **Testnet TAO Faucet**: <https://app.minersunion.ai/testnet-faucet>

Simply visit the faucet and request testnet TAO to your wallet address. You'll need TAO in your wallet to pay for subnet registration.

### Installing `uv`

If you don't have `uv` installed, you can install it with:

**macOS/Linux:**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Or via pip:**

```bash
pip install uv
```

After installation, restart your terminal or run `source ~/.bashrc` (or `source ~/.zshrc` on macOS).

## Installation

### Option 1: Using `uv` (Recommended)

`uv` automatically manages virtual environments - no need to create one manually! It will create a `.venv` directory in the project and handle all dependency isolation.

```bash
cd cartha-cli
uv sync  # Creates .venv automatically and installs dependencies
```

Then use `uv run` to execute commands (it automatically uses the project's virtual environment):

```bash
uv run cartha --help  # Runs in the project's virtual environment
```

### Option 2: Using `pip`

```bash
cd cartha-cli
pip install -e .
```

## Testnet Configuration

### Environment Variables

Set the following environment variables:

```bash
# Required: Testnet verifier URL
export CARTHA_VERIFIER_URL="https://cartha-verifier-826542474079.us-central1.run.app"

# Required: Bittensor network configuration
export CARTHA_NETWORK="test"  # Use "test" for testnet
export CARTHA_NETUID=78       # Testnet subnet UID

# Optional: Custom wallet path
export BITTENSOR_WALLET_PATH="/path/to/wallet"
```

### Verify Configuration

```bash
# Check CLI can access verifier
uv run cartha --help

# Test verifier connectivity
curl "${CARTHA_VERIFIER_URL}/health"
```

## Testnet Workflow

### Step 1: Register Your Hotkey

Register your hotkey to the testnet subnet:

```bash
uv run cartha miner register \
  --wallet-name <your-wallet-name> \
  --wallet-hotkey <your-hotkey-name> \
  --network test \
  --netuid 78
```

This will:

- Register your hotkey to subnet 78 (testnet)
- Fetch your slot UID
- Display your registration details

**Save the output** - you'll need your slot UID.

### Step 2: Lock Funds Using New Flow

Use the new interactive lock flow to create a lock position:

```bash
uv run cartha vault lock \
  --coldkey <your-coldkey-name> \
  --hotkey <your-hotkey-name> \
  --pool-id BTC/USD \
  --amount 100.0 \
  --lock-days 30 \
  --owner-evm 0xYourEVMAddress \
  --chain-id 8453 \
  --vault-address 0xVaultContractAddress
```

This command will:

1. **Check Registration**: Verify your hotkey is registered on the subnet
2. **Authenticate**: Sign a challenge message with your Bittensor hotkey to get a session token
3. **Request Signature**: Get an EIP-712 LockRequest signature from the verifier
4. **Display Transactions**: Show you the `USDC.approve` and `CarthaVault.lock` transaction data
5. **Execute in MetaMask**: You'll execute these transactions in MetaMask (or your EVM wallet)
6. **Poll Status**: Automatically poll for transaction confirmation and verification

**Note**: You'll need to have USDC in your EVM wallet and approve the vault to spend it. The CLI will display the exact transaction data for you to copy into MetaMask.

### Step 3: Check Miner Status

Verify your miner status (no authentication required):

```bash
uv run cartha miner status \
  --wallet-name <your-wallet-name> \
  --wallet-hotkey <your-hotkey-name>

# Or with explicit slot UID
uv run cartha miner status \
  --wallet-name <your-wallet-name> \
  --wallet-hotkey <your-hotkey-name> \
  --slot <your-slot-uid>
```

This will show:

- Miner state and pool information
- All active pools with amounts and expiration dates
- Days remaining countdown (with warnings for expiring pools)

## Pool IDs

Pool IDs can be specified as either:
- **Human-readable names**: `BTC/USD`, `EUR/USD`, `ETH/USDC`, etc.
- **Hex strings**: `0x...` (32 bytes)

The CLI automatically converts readable names to hex format. See `testnet/pool_ids.py` for available pool mappings.

## Common Commands

### Check CLI Version

```bash
uv run cartha version
```

### View Help

```bash
uv run cartha --help
uv run cartha miner register --help
uv run cartha vault lock --help
uv run cartha miner status --help
```

### Register (Burned Registration)

```bash
uv run cartha miner register \
  --wallet-name <name> \
  --wallet-hotkey <hotkey> \
  --network test \
  --netuid 78 \
  --burned
```

## Troubleshooting

### "Verifier URL not found"

**Problem**: CLI can't connect to verifier

**Solution**:

```bash
# Verify environment variable is set
echo $CARTHA_VERIFIER_URL

# Test verifier connectivity
curl "${CARTHA_VERIFIER_URL}/health"

# If using a different URL, update it
export CARTHA_VERIFIER_URL="https://cartha-verifier-826542474079.us-central1.run.app"
```

### "Hotkey not registered"

**Problem**: Hotkey is not registered on the subnet

**Solution**:

- Register your hotkey first using `cartha miner register`
- Verify you're using the correct network (`test`) and netuid (`78`)
- Check that you have testnet TAO in your wallet

### "Wallet not found"

**Problem**: CLI can't find your Bittensor wallet

**Solution**:

```bash
# Check default wallet location
ls ~/.bittensor/wallets/

# Or set custom path
export BITTENSOR_WALLET_PATH="/path/to/wallet"
```

### "Network error"

**Problem**: Can't connect to Bittensor network

**Solution**:

- Verify `CARTHA_NETWORK` is set to `"test"` for testnet
- Check your internet connection
- Try using a VPN if network is blocked

### "Transaction failed"

**Problem**: MetaMask transaction failed

**Solution**:

- Ensure you have enough USDC in your wallet
- Check that you've approved the vault to spend USDC
- Verify the transaction data matches what the CLI displayed
- Check gas fees and network congestion

## Testing Your Setup

### Quick Test

```bash
# 1. Register
uv run cartha miner register --wallet-name test --wallet-hotkey test --network test --netuid 78

# 2. Check miner status (no authentication needed)
uv run cartha miner status --wallet-name test --wallet-hotkey test

# 3. Lock funds (interactive flow)
uv run cartha vault lock \
  --coldkey test \
  --hotkey test \
  --pool-id BTC/USD \
  --amount 100.0 \
  --lock-days 30 \
  --owner-evm 0xYourEVMAddress \
  --chain-id 8453 \
  --vault-address 0xVaultContractAddress
```

## Next Steps

- Check the [Main README](../README.md) for advanced usage
- Review [Validator Setup](../../cartha-validator/docs/TESTNET_SETUP.md) if running a validator
- Provide feedback via [GitHub Issues](https://github.com/your-org/cartha-cli/issues)

## Additional Resources

- [CLI README](../README.md) - Full CLI documentation
- `testnet/pool_ids.py` - Pool ID helper functions for converting between readable names and hex format
