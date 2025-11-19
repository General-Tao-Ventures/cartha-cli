# Cartha CLI - Testnet Setup Guide

This guide will help you set up and use the Cartha CLI on the public testnet. This folder contains helper scripts and complete instructions for testing the Cartha subnet.

## Prerequisites

- Python 3.11
- [`uv`](https://github.com/astral-sh/uv) package manager (or `pip`)
- Bittensor wallet (for subnet registration)
- Access to the testnet verifier URL
- Testnet TAO (required for subnet registration)

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

# Optional: EVM private key (for demo - will be generated in Step 2)
export CARTHA_EVM_PK="your-demo-evm-private-key"

# Optional: Custom wallet path
export BITTENSOR_WALLET_PATH="/path/to/wallet"
```

### Verify Configuration

```bash
# Check CLI can access verifier
uv run cartha --help

# Test verifier connection
curl "${CARTHA_VERIFIER_URL}/health"
```

## Testnet Workflow

### Step 0: Get Testnet TAO (if needed)

Before registering, make sure you have testnet TAO in your wallet. If you need testnet TAO, visit the faucet:

🔗 **Testnet TAO Faucet**: <https://app.minersunion.ai/testnet-faucet>

### Step 1: Register Your Hotkey

Register your hotkey to the testnet subnet:

```bash
uv run cartha register \
  --wallet-name <your-wallet-name> \
  --wallet-hotkey <your-hotkey-name> \
  --network test \
  --netuid 78
```

This will:

- Register your hotkey to subnet 78 (testnet)
- Fetch your slot UID
- Retrieve your pair password
- Display your registration details

**Save the output** - you'll need:

- Slot UID
- Pair password (starts with `0x`)

### Step 2: Generate Demo EVM Key

For testnet, you can use a demo EVM key. Use the helper script in this folder:

```bash
# From cartha-cli repository root
uv run python testnet/create_demo_evm_key.py --output testnet/outputs/evm_key.json
```

This creates a demo private key and address. Export it:

```bash
export CARTHA_EVM_PK=$(jq -r .CARTHA_EVM_PK testnet/outputs/evm_key.json)
export CARTHA_DEMO_EVM_ADDRESS=$(jq -r .CARTHA_DEMO_EVM_ADDRESS testnet/outputs/evm_key.json)
```

### Step 3: Build Lock Proof

Create a lock proof using demo data:

```bash
# From cartha-cli repository root
uv run python testnet/build_lock_proof.py \
  --hotkey <your-hotkey-ss58> \
  --slot <your-slot-uid> \
  --pwd <your-pair-password>
```

This will:

- Generate a mock lock proof payload
- Sign it with your demo EVM key
- Save the payload to `testnet/outputs/lock_proof_payload.json`

### Step 4: Submit Lock Proof

Submit your lock proof to the verifier:

```bash
# Load payload
PAYLOAD=$(cat testnet/outputs/lock_proof_payload.json)

# Submit using CLI
uv run cartha prove-lock \
  --chain $(jq -r .chain testnet/outputs/lock_proof_payload.json) \
  --vault $(jq -r .vault testnet/outputs/lock_proof_payload.json) \
  --tx $(jq -r .tx testnet/outputs/lock_proof_payload.json) \
  --amount $(jq -r .amountNormalized testnet/outputs/lock_proof_payload.json) \
  --hotkey $(jq -r .hotkey testnet/outputs/lock_proof_payload.json) \
  --slot $(jq -r .slot testnet/outputs/lock_proof_payload.json) \
  --miner-evm $(jq -r .miner_evm testnet/outputs/lock_proof_payload.json) \
  --pwd $(jq -r .password testnet/outputs/lock_proof_payload.json) \
  --signature $(jq -r .signature testnet/outputs/lock_proof_payload.json)
```

Or use the command printed by `build_lock_proof.py`.

### Step 5: Check Pair Status

Verify your pair status:

```bash
uv run cartha pair status \
  --wallet-name <your-wallet-name> \
  --wallet-hotkey <your-hotkey-name> \
  --hotkey <your-hotkey-ss58> \
  --slot <your-slot-uid>
```

## Helper Scripts

This folder contains helper scripts for testing the Cartha CLI on the public testnet.

### `create_demo_evm_key.py`

Generates a throwaway EVM keypair for demo purposes. This key is used to sign lock proofs in testnet mode.

**Usage:**

```bash
# From cartha-cli repository root
uv run python testnet/create_demo_evm_key.py --output testnet/outputs/evm_key.json

# Export the key to your environment
export CARTHA_EVM_PK=$(jq -r .CARTHA_EVM_PK testnet/outputs/evm_key.json)
export CARTHA_DEMO_EVM_ADDRESS=$(jq -r .CARTHA_DEMO_EVM_ADDRESS testnet/outputs/evm_key.json)
```

**Options:**

- `--output` - Path to write JSON blob containing `CARTHA_EVM_PK` and address
- `--overwrite` - Allow overwriting an existing output file

### `build_lock_proof.py`

Assembles and signs a demo LockProof payload with mock data. This creates a lock proof that can be submitted to the testnet verifier.

**Usage:**

```bash
# From cartha-cli repository root
uv run python testnet/build_lock_proof.py \
  --hotkey <your-hotkey-ss58> \
  --slot <your-slot-uid> \
  --pwd <your-pair-password>

# The script will print the command to submit the proof
```

**Options:**

- `--chain` - EVM chain ID (default: 31337 for demo)
- `--vault` - Vault contract address (default: `0x00000000000000000000000000000000000000aa`)
- `--tx` - Transaction hash (default: mock hash)
- `--amount` - Deposit amount in USDC (default: 250)
- `--hotkey` - Miner hotkey (SS58) - required
- `--slot` - Miner slot UID - required
- `--pwd` - Pair password (0x...) - required
- `--output` - Output file path (default: `testnet/outputs/lock_proof_payload.json`)

## Outputs

Generated files are saved to `testnet/outputs/` (this folder is gitignored):

- `evm_key.json` - Generated EVM keypair with `CARTHA_EVM_PK` and `CARTHA_DEMO_EVM_ADDRESS`
- `lock_proof_payload.json` - Lock proof payload ready for submission

## Demo Mode Notes

The testnet runs in **demo mode**, which means:

- ✅ Mock vault addresses are accepted
- ✅ Mock transaction hashes work
- ✅ On-chain validation is bypassed
- ✅ No real USDC locking required

### Demo Configuration

The demo uses these defaults:

- **Chain ID**: 31337 (local/test)
- **Vault**: `0x00000000000000000000000000000000000000aa`
- **Transaction**: Mock hash
- **Amount**: 250 USDC (default)

You can override these in `build_lock_proof.py`:

```bash
uv run python testnet/build_lock_proof.py \
  --chain 31337 \
  --vault 0x00000000000000000000000000000000000000aa \
  --tx 0x1111111111111111111111111111111111111111111111111111111111111111 \
  --amount 500 \
  --hotkey <hotkey> --slot <slot> --pwd <password>
```

## Common Commands

### Check CLI Version

```bash
uv run cartha version
```

### View Help

```bash
uv run cartha --help
uv run cartha register --help
uv run cartha prove-lock --help
uv run cartha pair status --help
```

### Register (Burned Registration)

```bash
uv run cartha register \
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

### "Invalid pair password"

**Problem**: Pair password mismatch

**Solution**:

- Re-register to get a new pair password
- Ensure you're using the correct hotkey/slot combination
- Check that the verifier HMAC key hasn't changed

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

### "Signature verification failed"

**Problem**: Lock proof signature is invalid

**Solution**:

- Ensure `CARTHA_EVM_PK` matches the key used to sign
- Regenerate the lock proof with `build_lock_proof.py`
- Verify the signature in the payload JSON

## Testing Your Setup

### Quick Test

```bash
# 1. Register
uv run cartha register --wallet-name test --wallet-hotkey test --network test --netuid 78

# 2. Check pair status
uv run cartha pair status --wallet-name test --wallet-hotkey test \
  --hotkey <hotkey-from-registration> --slot <slot-from-registration>

# 3. Generate demo key
uv run python testnet/create_demo_evm_key.py --output testnet/outputs/evm_key.json
export CARTHA_EVM_PK=$(jq -r .CARTHA_EVM_PK testnet/outputs/evm_key.json)

# 4. Build and submit proof
uv run python testnet/build_lock_proof.py --hotkey <hotkey> --slot <slot> --pwd <password>
# Then submit using the printed command
```

## Next Steps

- Check the [Main README](../README.md) for advanced usage
- Review [Validator Setup](../../cartha-subnet-validator/docs/TESTNET_SETUP.md) if running a validator
- Provide feedback via [GitHub Issues](https://github.com/your-org/cartha-cli/issues)

## Additional Resources

- [CLI README](../README.md) - Full CLI documentation
- Testnet helper scripts are in this `testnet/` folder:
  - `testnet/create_demo_evm_key.py` - Generate demo EVM keys
  - `testnet/build_lock_proof.py` - Build lock proof payloads
