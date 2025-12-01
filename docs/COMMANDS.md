# Cartha CLI Command Reference

Complete documentation for all Cartha CLI commands and their arguments.

## Table of Contents

- [Command Groups](#command-groups)
- [Miner Commands](#miner-commands)
  - [cartha miner register](#cartha-miner-register)
  - [cartha miner status](#cartha-miner-status)
  - [cartha miner password](#cartha-miner-password)
- [Vault Commands](#vault-commands)
  - [cartha vault lock](#cartha-vault-lock)
  - [cartha vault claim](#cartha-vault-claim)
- [Other Commands](#other-commands)
- [cartha version](#cartha-version)
  - [cartha pair status](#cartha-pair-status-legacy)
- [Environment Variables](#environment-variables)
- [Common Workflows](#common-workflows)

---

## Command Groups

The CLI is organized into logical command groups with short aliases:

- **`cartha miner`** (or **`cartha m`**) - Miner management commands
- **`cartha vault`** (or **`cartha v`**) - Vault management commands

---

## Miner Commands

### cartha miner register

Register a hotkey on the Cartha subnet and obtain your pair password.

#### Usage

```bash
cartha miner register [OPTIONS]
# or
cartha m register [OPTIONS]
```

#### Options

| Option | Type | Required | Description |
| --- | --- | --- | --- |
| `--wallet-name`, `--wallet.name` | string | Yes | Coldkey wallet name |
| `--wallet-hotkey`, `--wallet.hotkey` | string | Yes | Hotkey name within the wallet |
| `--network` | string | No | Bittensor network name (default: `finney`) |
| `--netuid` | integer | No | Subnet netuid (default: `35`) |
| `--pow` | flag | No | Use PoW registration instead of burned registration |
| `--cuda` | flag | No | Enable CUDA for PoW registration |

#### Examples

```bash
# Register with burned TAO (default)
cartha miner register \
  --wallet-name cold \
  --wallet-hotkey hot \
  --network finney \
  --netuid 35

# Register with PoW
cartha miner register \
  --wallet-name cold \
  --wallet-hotkey hot \
  --pow \
  --cuda

# Using short alias
cartha m register --wallet-name cold --wallet-hotkey hot
```

#### What It Does

1. Loads your wallet and validates hotkey ownership
2. Checks if the hotkey is already registered
3. Performs registration (burned TAO or PoW)
4. Retrieves the assigned UID from the metagraph
5. Generates a pair password from the verifier
6. Displays the UID and pair password

**Important:** Keep your pair password secure. It's required for all verifier interactions and exposure could allow others to steal your locked USDC rewards.

---

### cartha miner status

Check your miner status and pool information **without requiring authentication**. This is the fastest way to check your miner's status, active pools, expiration dates, and password issuance status.

#### Usage

```bash
cartha miner status [OPTIONS]
# or
cartha m status [OPTIONS]
```

#### Options

| Option | Type | Required | Description |
| --- | --- | --- | --- |
| `--wallet-name`, `--wallet.name` | string | Yes | Coldkey wallet name |
| `--wallet-hotkey`, `--wallet.hotkey` | string | Yes | Hotkey name within the wallet |
| `--slot` | integer | No | Subnet UID assigned to the miner (auto-fetched if not provided) |
| `--auto-fetch-uid` | flag | No | Automatically fetch UID from Bittensor network (default: enabled) |
| `--network` | string | No | Bittensor network name (default: `finney`) |
| `--netuid` | integer | No | Subnet netuid (default: `35`) |
| `--json` | flag | No | Emit the raw JSON response |

#### Examples

```bash
# Quick status check (no authentication, auto-fetches UID)
cartha miner status \
  --wallet-name cold \
  --wallet-hotkey hot

# Using short alias
cartha m status --wallet-name cold --wallet-hotkey hot

# With explicit slot UID
cartha miner status \
  --wallet-name cold \
  --wallet-hotkey hot \
  --slot 123

# JSON output
cartha miner status \
  --wallet-name cold \
  --wallet-hotkey hot \
  --json
```

#### Output

The command displays:

- **Miner Status Table:**
  - Hotkey address
  - Slot UID
  - State (active, verified, pending, unknown)
  - EVM address(es) used for locking
  - Password issued status (yes/no)
  - Password issued timestamp (if applicable)

- **Active Pools Table** (if pools exist):
  - Pool name (human-readable, e.g., "EURUSD", "BTCUSDC")
  - Amount locked (USDC)
  - Lock days
  - Expiration date with days remaining countdown
    - ⚠ Red warning if < 7 days remaining
    - ⚠ Yellow warning if < 15 days remaining
  - Status (Active / In Next Epoch)
  - EVM address used for that pool

- **Reminders:**
  - Lock expiration behavior
  - Top-up/extension information
  - Multi-pool guidance (if applicable)
  - Password viewing instructions

#### Key Features

- ✅ **No authentication required** - Fast status checks without signature verification
- ✅ **Multi-pool support** - View all your active pools in one command
- ✅ **Expiration countdown** - See days remaining with color-coded warnings
- ✅ **Password never displayed** - Security by default
- ✅ **Auto-fetches UID** - No need to remember your slot UID

#### What It Does

1. Loads your wallet to get the hotkey address
2. Automatically fetches your slot UID from the Bittensor network (or prompts if disabled)
3. Queries the verifier's public `/v1/miner/status` endpoint (no signature required)
4. Displays comprehensive miner and pool information
5. Shows expiration warnings for pools expiring soon

---

### cartha miner password

View your pair password **with authentication**. This command requires Bittensor signature verification to display the actual password and its issuance date. If no password exists, it will prompt you to create one.

#### Usage

```bash
cartha miner password [OPTIONS]
# or
cartha m password [OPTIONS]
```

#### Options

| Option | Type | Required | Description |
| --- | --- | --- | --- |
| `--wallet-name`, `--wallet.name` | string | Yes | Coldkey wallet name |
| `--wallet-hotkey`, `--wallet.hotkey` | string | Yes | Hotkey name within the wallet |
| `--slot` | integer | No | Subnet UID assigned to the miner (auto-fetched if not provided) |
| `--auto-fetch-uid` | flag | No | Automatically fetch UID from Bittensor network (default: enabled) |
| `--network` | string | No | Bittensor network name (default: `finney`) |
| `--netuid` | integer | No | Subnet netuid (default: `35`) |
| `--json` | flag | No | Emit the raw JSON response |

#### Examples

```bash
# View password (requires authentication)
cartha miner password \
  --wallet-name cold \
  --wallet-hotkey hot

# Using short alias
cartha m password --wallet-name cold --wallet-hotkey hot

# With explicit slot UID
cartha miner password \
  --wallet-name cold \
  --wallet-hotkey hot \
  --slot 123
```

#### Output

- Pair password (hex string starting with `0x`)
- Password issuance timestamp
- Security reminder to keep password safe

#### When to Use

- When you need to view your password (e.g., for signing lock proofs)
- When you need to create a password for a newly registered hotkey
- When you've forgotten your password and need to retrieve it

**Security Note:** Use `cartha miner status` for quick checks. Only use `cartha miner password` when you actually need to view or create your password.

#### What It Does

1. Loads your wallet and validates hotkey ownership
2. Signs a challenge message with your hotkey to prove ownership
3. Sends the signed challenge to the verifier
4. Retrieves and displays the pair password
5. If no password exists, prompts to create one

---

## Vault Commands

### cartha vault lock

Create a new lock position by interacting with the Cartha Verifier. This command guides you through the complete lock flow: registration check, authentication, signature request, and transaction execution.

#### Usage

```bash
cartha vault lock [OPTIONS]
# or
cartha v lock [OPTIONS]
```

#### Options

| Option | Type | Required | Description |
| --- | --- | --- | --- |
| `--coldkey`, `-c` | string | Yes | Coldkey wallet name |
| `--hotkey`, `-h` | string | Yes | Hotkey name within the wallet |
| `--pool-id` | string | Yes | Pool ID (readable name like 'BTC/USD' or hex string like '0x...') |
| `--amount` | string | Yes | Amount of USDC to lock (e.g., '100.0') |
| `--lock-days` | integer | Yes | Number of days to lock (7-365) |
| `--owner-evm` | string | Yes | EVM address that will own the lock position |
| `--chain-id` | integer | Yes | EVM chain ID where the vault is deployed |
| `--vault-address` | string | Yes | CarthaVault contract address |
| `--json` | flag | No | Emit responses as JSON |

#### Examples

```bash
# Basic usage
cartha vault lock \
  --coldkey my-coldkey \
  --hotkey my-hotkey \
  --pool-id BTC/USD \
  --amount 100.0 \
  --lock-days 30 \
  --owner-evm 0x1234567890123456789012345678901234567890 \
  --chain-id 8453 \
  --vault-address 0xabcdef1234567890abcdef1234567890abcdef12

# Using short alias
cartha v lock \
  -c my-coldkey \
  -h my-hotkey \
  --pool-id ETH/USDC \
  --amount 250.5 \
  --lock-days 365 \
  --owner-evm 0xEVM... \
  --chain-id 8453 \
  --vault-address 0xVAULT...

# JSON output mode
cartha vault lock \
  --coldkey my-coldkey \
  --hotkey my-hotkey \
  --pool-id BTC/USD \
  --amount 100.0 \
  --lock-days 30 \
  --owner-evm 0xEVM... \
  --chain-id 8453 \
  --vault-address 0xVAULT... \
  --json
```

#### What It Does

1. **Registration Check**: Verifies your hotkey is registered on the Bittensor subnet
2. **Bittensor Authentication**: Signs a challenge message with your hotkey and receives a session token
3. **Request Signature**: Sends lock parameters to the verifier, which signs an EIP-712 LockRequest
4. **User Confirmation**: Displays lock details and prompts for confirmation
5. **Transaction Display**: Shows transaction data for `USDC.approve` and `CarthaVault.lock` to execute in MetaMask
6. **Status Polling**: Automatically polls the verifier for transaction status until verified
7. **Auto-Processing**: Verifier automatically detects `LockCreated` events and adds miner to upcoming epoch

**Note**: You'll need to execute the `USDC.approve` and `CarthaVault.lock` transactions in MetaMask (or your EVM wallet) using the transaction data displayed by the CLI.

#### Troubleshooting

##### Signature Mismatch / Funds Locked But Not Credited

If you request a new signature after already requesting one, the old signature becomes invalid. If you execute a transaction using an old signature:

- ✅ **Transaction will succeed** - Your funds are safely locked in the vault contract
- ❌ **Miner won't be credited** - The verifier won't automatically match the transaction to your miner

**What to do:**

1. **Open a support ticket** on our Discord channel

2. **Provide the following information:**
   - Transaction hash (0x...)
   - Your Bittensor hotkey (SS58 address)
   - Your miner slot UID
   - Chain ID and vault address
   - Pool ID
   - EVM address (owner address)

3. **Prove ownership with signatures:**
   
   **Bittensor Hotkey Signature:**
   ```bash
   btcli w sign --wallet.name <your-coldkey> --wallet.hotkey <your-hotkey> --text "Cartha lock recovery: <tx-hash>"
   ```
   Provide both the signature and the message text.
   
   **EVM Address Signature:**
   Sign the following message with MetaMask or your Web3 wallet:
   ```
   Cartha lock recovery: <tx-hash>
   ```
   Provide both the signature and the message text.

4. **Admin will verify signatures** and manually recover your lock to credit your miner

**Prevention:**

- Always use the **most recent signature** from `cartha vault lock`
- If you request a new signature, discard the old one
- Don't execute transactions with old signatures after requesting new ones

---

## Other Commands

### cartha version

Display the CLI version information.

#### Usage

```bash
cartha version
```

#### Output

Displays the current version of the Cartha CLI.

---

### cartha pair status *(Legacy)*

Legacy command for checking pair status. **Deprecated** - use `cartha miner status` instead for faster, unauthenticated status checks, or `cartha miner password` if you need to view the password.

#### Usage

```bash
cartha pair status [OPTIONS]
```

#### Options

Same as `cartha miner status`, but requires authentication. See [cartha miner status](#cartha-miner-status) for details.

**Note:** This command is maintained for backward compatibility but is not recommended for new workflows.

---

## Environment Variables

The following environment variables can be set to configure the CLI:

| Variable | Description | Default |
| --- | --- | --- |
| `CARTHA_VERIFIER_URL` | Verifier endpoint URL | `https://cartha-verifier-826542474079.us-central1.run.app` |
| `CARTHA_NETWORK` | Bittensor network name | `finney` |
| `CARTHA_NETUID` | Subnet netuid | `35` |
| `CARTHA_EVM_PK` | EVM private key for local signing (optional) | - |
| `BITTENSOR_WALLET_PATH` | Override wallet path if keys are not in the default location | - |

### Setting Environment Variables

```bash
# Linux/macOS
export CARTHA_VERIFIER_URL="https://cartha-verifier-826542474079.us-central1.run.app"
export CARTHA_NETWORK="finney"
export CARTHA_NETUID="35"

# Windows (PowerShell)
$env:CARTHA_VERIFIER_URL="https://cartha-verifier-826542474079.us-central1.run.app"
$env:CARTHA_NETWORK="finney"
$env:CARTHA_NETUID="35"

# Using .env file (recommended)
# Create a .env file in your project root:
CARTHA_VERIFIER_URL=https://cartha-verifier-826542474079.us-central1.run.app
CARTHA_NETWORK=finney
CARTHA_NETUID=35
```

---

## Common Workflows

### First-Time Setup

1. **Register your hotkey:**
   ```bash
   cartha miner register --wallet-name cold --wallet-hotkey hot
   ```
   Save the displayed pair password securely.

2. **Check your miner status:**
   ```bash
   cartha miner status --wallet-name cold --wallet-hotkey hot
   ```
   This shows your status without requiring authentication.

3. **View your password when needed:**
   ```bash
   cartha miner password --wallet-name cold --wallet-hotkey hot
   ```
   Use this only when you need to view or create your password.

### Creating a Lock Position

1. **Request signature and execute transaction:**
   ```bash
   cartha vault lock \
     --coldkey my-coldkey \
     --hotkey my-hotkey \
     --pool-id BTC/USD \
     --amount 250.0 \
     --lock-days 30 \
     --owner-evm 0xYourEVMAddress \
     --chain-id 8453 \
     --vault-address 0xVaultAddress
   ```

2. **Execute transactions in MetaMask** using the transaction data displayed by the CLI

3. **Wait for auto-detection** - The verifier will automatically detect your `LockCreated` event and add you to the upcoming epoch

**⚠️ Important:** If you request a new signature after already requesting one, make sure to use the **newest signature only**. Using an old signature will lock your funds but won't credit your miner automatically. In this case, open a support ticket on Discord for manual recovery. You'll need to provide:
- Transaction hash and all lock details
- Bittensor hotkey signature (via `btcli w sign`)
- EVM address signature (via MetaMask or Web3 wallet)

### Checking Pool Status and Expiration

1. **Quick status check (no authentication):**
   ```bash
   cartha miner status --wallet-name cold --wallet-hotkey hot
   ```

2. **View all your pools:**
   - See all active pools in one table
   - Check expiration dates with days remaining countdown
   - Identify pools expiring soon (red/yellow warnings)
   - View EVM addresses used for each pool

3. **Monitor expiration:**
   - Pools expiring in < 7 days show red warning
   - Pools expiring in < 15 days show yellow warning
   - Expired pools stop earning rewards automatically

### Extending Your Lock Period

1. **Check your current lock status:**
   ```bash
   cartha miner status --wallet-name cold --wallet-hotkey hot
   ```

2. **Top-ups/extensions happen automatically on-chain** - no CLI action needed!
   - Make a top-up or extend transaction on the vault contract
   - The verifier automatically detects `LockUpdated` events
   - Your updated amount/lock_days will be reflected in `miner status` within 30 seconds

### Multi-Pool Management

1. **View all pools:**
   ```bash
   cartha miner status --wallet-name cold --wallet-hotkey hot
   ```

2. **Each pool is tracked separately:**
   - Each pool has its own expiration date
   - Expired pools stop earning rewards, others continue
   - You can have multiple pools active simultaneously
   - Each pool can use a different EVM address

### Using Payload Files

For testnet or automated workflows:

1. **Generate payload file:**
   ```bash
   python testnet/build_lock_proof.py
   ```

2. **Submit using payload file:**
   ```bash
   cartha vault lock --payload-file testnet/outputs/lock_proof_payload.json
   ```

---

## Troubleshooting

### Wallet Not Found

Ensure your Bittensor wallet files exist in the default location or set `BITTENSOR_WALLET_PATH`:

```bash
export BITTENSOR_WALLET_PATH="/path/to/your/wallets"
```

### Pair Password Not Found

If `miner status` shows "Password issued: no", use `miner password` to create one:

```bash
cartha miner password --wallet-name cold --wallet-hotkey hot
```

### Signature Generation Fails

- Ensure `eth-account` is installed: `uv sync`
- For local signing, verify `CARTHA_EVM_PK` is set correctly
- For external signing, follow the instructions in the generated files

### Verifier Connection Errors

- Check `CARTHA_VERIFIER_URL` is set correctly
- Verify network connectivity
- Check verifier status: `curl $CARTHA_VERIFIER_URL/health`

### UID Auto-Fetch Fails

If automatic UID fetching fails:

1. Check network connectivity to Bittensor network
2. Verify your hotkey is registered: `cartha miner status --no-auto-fetch-uid`
3. Manually provide slot UID: `cartha miner status --slot 123`

---

## Command Comparison

| Feature | `miner status` | `miner password` | `pair status` (legacy) |
| --- | --- | --- | --- |
| Authentication | ❌ Not required | ✅ Required | ✅ Required |
| Speed | ⚡ Fast | 🐌 Slower | 🐌 Slower |
| Password Display | ❌ Never | ✅ Yes | ✅ Yes |
| Pool Information | ✅ Yes | ❌ No | ✅ Yes |
| Expiration Warnings | ✅ Yes | ❌ No | ✅ Yes |
| Recommended | ✅ Yes | ✅ When needed | ❌ Deprecated |

**Recommendation:** Use `cartha miner status` for daily checks, and `cartha miner password` only when you need to view or create your password.

---

For more help, see [Feedback & Support](FEEDBACK.md).
