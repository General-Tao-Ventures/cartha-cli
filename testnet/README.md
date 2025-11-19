# Cartha CLI Testnet Helper Scripts

This folder contains helper scripts for testing the Cartha CLI on the public testnet.

## Scripts

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
- `--vault` - Vault contract address (default: mock address)
- `--tx` - Transaction hash (default: mock hash)
- `--amount` - Deposit amount in USDC (default: 250)
- `--hotkey` - Miner hotkey (SS58) - required
- `--slot` - Miner slot UID - required
- `--pwd` - Pair password (0x...) - required
- `--output` - Output file path (default: `testnet/outputs/lock_proof_payload.json`)

## Outputs

Generated files are saved to `testnet/outputs/` (this folder is gitignored):

- `evm_key.json` - Generated EVM keypair
- `lock_proof_payload.json` - Lock proof payload ready for submission

## Requirements

- `cartha-cli` installed (`uv sync`)
- Environment variable `CARTHA_EVM_PK` set (or use `--hotkey`, `--slot`, `--pwd` flags)
- Testnet verifier URL configured (`CARTHA_VERIFIER_URL`)

## Demo Mode

These scripts are designed for **demo mode** testing:

- ✅ Uses mock vault addresses
- ✅ Uses mock transaction hashes
- ✅ No real USDC locking required
- ✅ Works with `DEMO_SKIP_LOCKPROOF=1` on the verifier

See the [Testnet Setup Guide](../docs/TESTNET_SETUP.md) for complete instructions.

