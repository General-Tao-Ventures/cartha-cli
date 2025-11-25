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
uv run cartha miner register \
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

Submit your lock proof to the verifier. The easiest way is to use the `--payload-file` option:

```bash
# Simple: Use the payload file directly (recommended)
uv run cartha vault lock --payload-file testnet/outputs/lock_proof_payload.json
```

The `build_lock_proof.py` script will print this command for you after generating the payload. This automatically loads all required fields (including the timestamp) from the JSON file.

**Alternative: Manual submission**

If you prefer to specify parameters manually, you can use the full command printed by `build_lock_proof.py`:

```bash
uv run cartha vault lock \
  --chain <chain-id> \
  --vault <vault-address> \
  --tx <tx-hash> \
  --amount <amount> \
  --hotkey <hotkey> \
  --slot <slot> \
  --miner-evm <evm-address> \
  --pwd <password> \
  --timestamp <timestamp> \
  --signature <signature>
```

**Note**: When using manual parameters, you must include the `--timestamp` option with the exact timestamp used when signing the proof (this is automatically handled when using `--payload-file`).

### Step 5: Check Miner Status

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
- Password issuance status (but never displays the password)

**Note:** Use `cartha miner password` if you need to view your actual password.

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

# The script will print a simple command to submit the proof using --payload-file
```

**Options:**

- `--chain` - EVM chain ID (default: 31337 for demo)
- `--vault` - Vault contract address (default: `0x00000000000000000000000000000000aa`)
- `--tx` - Transaction hash (default: mock hash)
- `--amount` - Deposit amount in USDC (if not provided, you'll be prompted with a random default between 100-9999)
- `--hotkey` - Miner hotkey (SS58) - required
- `--slot` - Miner slot UID - required
- `--pwd` - Pair password (0x...) - required
- `--output` - Output file path (default: `testnet/outputs/lock_proof_payload.json`)

**Output:**

The script saves a JSON payload file and prints a simple command to submit it:

```bash
uv run cartha vault lock --payload-file testnet/outputs/lock_proof_payload.json
```

This command automatically loads all required fields (including the timestamp) from the payload file, making it much easier than manually specifying all parameters.

## Outputs

Generated files are saved to `testnet/outputs/` (this folder is gitignored to prevent accidentally committing sensitive data):

- `evm_key.json` - Generated EVM keypair with `CARTHA_EVM_PK` and `CARTHA_DEMO_EVM_ADDRESS`
- `lock_proof_payload.json` - Lock proof payload ready for submission (contains signature, password, timestamp, etc.)

**Important**: These files contain sensitive information (private keys, signatures, passwords). They are automatically ignored by git, but make sure not to share them publicly.

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
- **Amount**: Random between 100-9999 USDC (prompted if not specified)

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
uv run cartha miner register --help
uv run cartha vault lock --help
uv run cartha miner status --help
```

### Submit Lock Proof (Using Payload File)

The easiest way to submit a lock proof is using the `--payload-file` option:

```bash
uv run cartha vault lock --payload-file testnet/outputs/lock_proof_payload.json
```

This automatically loads all required fields (chain, vault, tx, amount, hotkey, slot, miner_evm, password, timestamp, signature) from the JSON file generated by `build_lock_proof.py`.

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
uv run cartha miner register --wallet-name test --wallet-hotkey test --network test --netuid 78

# 2. Check miner status (no authentication needed)
uv run cartha miner status --wallet-name test --wallet-hotkey test

# 3. Generate demo key
uv run python testnet/create_demo_evm_key.py --output testnet/outputs/evm_key.json
export CARTHA_EVM_PK=$(jq -r .CARTHA_EVM_PK testnet/outputs/evm_key.json)

# 4. Build and submit proof
uv run python testnet/build_lock_proof.py --hotkey <hotkey> --slot <slot> --pwd <password>
# Then submit using the simple command printed by the script:
uv run cartha vault lock --payload-file testnet/outputs/lock_proof_payload.json
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
