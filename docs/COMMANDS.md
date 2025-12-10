# Cartha CLI Command Reference

Complete documentation for all Cartha CLI commands and their arguments.

**Cartha is the Liquidity Provider for 0xMarkets DEX.** This CLI enables miners to provide liquidity and manage their mining operations on the Cartha subnet.

## Table of Contents

- [Command Groups](#command-groups)
- [Miner Commands](#miner-commands)
  - [cartha miner register](#cartha-miner-register)
  - [cartha miner status](#cartha-miner-status)
- [Vault Commands](#vault-commands)
  - [cartha vault pools](#cartha-vault-pools)
  - [cartha vault lock](#cartha-vault-lock)
  - [cartha vault claim](#cartha-vault-claim)
- [Utility Commands](#utility-commands)
  - [cartha utils health](#cartha-utils-health)
  - [cartha utils config](#cartha-utils-config)
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
- **`cartha utils`** (or **`cartha u`**) - Utility commands (health checks and configuration)

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

Check your miner status and pool information **without requiring authentication**. This is the fastest way to check your miner's status, active pools, expiration dates, and password issuance status. As a Liquidity Provider for 0xMarkets DEX, this shows your liquidity positions and mining status.

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

## Vault Commands

### cartha vault pools

Show current available pools with their pool IDs, vault addresses, and chain IDs.

#### Usage

```bash
cartha vault pools [OPTIONS]
# or
cartha v pools [OPTIONS]
```

#### Options

| Option | Type | Description |
| --- | --- | --- |
| `--json` | flag | Emit responses as JSON |

#### Examples

```bash
# List all available pools
cartha vault pools
# or
cartha v pools

# JSON output format
cartha vault pools --json
```

#### Output

The command displays all available pools in a multi-line format:

- **Pool Name**: Human-readable pool identifier (e.g., "BTCUSD", "ETHUSD")
- **Pool ID**: Full hex pool ID (66 characters: `0x` + 64 hex characters)
- **Vault Address**: Full vault contract address (42 characters: `0x` + 40 hex characters)
- **Chain ID**: EVM chain ID where the vault is deployed

#### Example Output

```
Available Pools

Pool 1: BTCUSD
  Pool ID:      0xee62665949c883f9e0f6f002eac32e00bd59dfe6c34e92a91c37d6a8322d6489
  Vault Address: 0x471D86764B7F99b894ee38FcD3cEFF6EAB321b69
  Chain ID:     84532

Pool 2: ETHUSD
  Pool ID:      0x0b43555ace6b39aae1b894097d0a9fc17f504c62fea598fa206cc6f5088e6e45
  Vault Address: 0xdB74B44957A71c95406C316f8d3c5571FA588248
  Chain ID:     84532

Pool 3: EURUSD
  Pool ID:      0xa9226449042e36bf6865099eec57482aa55e3ad026c315a0e4a692b776c318ca
  Vault Address: 0x3C4dAfAC827140B8a031d994b7e06A25B9f27BAD
  Chain ID:     84532
```

#### When to Use

- Before creating a lock position to see available pools
- To verify pool IDs and vault addresses for a specific pool
- To check which chain a pool is deployed on

---

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
| `--pool-id` | string | Yes | Pool ID (readable name like 'BTCUSD' or hex string like '0x...') |
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
  --pool-id BTCUSD \
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
  --pool-id BTCUSD \
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
5. **Open Frontend**: Automatically opens the Cartha Lock UI in your browser with pre-filled transaction parameters
6. **Phase 1 - Approve USDC**: The frontend guides you through approving USDC spending. The CLI automatically detects when approval is complete
7. **Phase 2 - Lock Position**: The frontend guides you through locking your USDC in the vault contract
8. **Auto-Processing**: Verifier automatically detects `LockCreated` events and adds miner to upcoming epoch

**Note**: The CLI opens a web interface (Cartha Lock UI) that handles both approval and lock transactions. You'll connect your wallet (MetaMask, Coinbase Wallet, Talisman, or WalletConnect) and execute the transactions directly in the browser. The CLI monitors the approval phase and automatically proceeds when complete.

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

## Utility Commands

### cartha utils health

Check CLI health: verifier connectivity, Bittensor network, and configuration.

This command verifies that all components needed for the CLI are working correctly. Use this command to diagnose connectivity issues or verify your configuration before using other commands.

#### Usage

```bash
cartha utils health [OPTIONS]
# or
cartha u health [OPTIONS]
```

#### Options

| Option | Type | Description |
| --- | --- | --- |
| `--verbose`, `-v` | flag | Show detailed troubleshooting information for failed checks |

#### Examples

```bash
# Basic health check
cartha utils health
# or
cartha u health

# Detailed health check with troubleshooting tips
cartha utils health --verbose
```

#### Output

The command performs five checks:

1. **Verifier Connectivity**
   - Tests connection to the configured verifier URL
   - Measures response latency
   - Verifies the verifier is reachable and responding

2. **Bittensor Network Connectivity**
   - Connects to the configured Bittensor network
   - Fetches current block number
   - Measures network latency
   - Validates network is operational

3. **Configuration Validation**
   - Verifies verifier URL format
   - Checks network is set
   - Validates netuid is positive
   - Reports any configuration issues

4. **Subnet Metadata**
   - Retrieves subnet information from the metagraph
   - Shows number of registered slots
   - Displays tempo (epoch length)
   - Shows current block number
   - Measures metadata fetch latency

5. **Environment Variables**
   - Checks which environment variables are set vs using defaults
   - Shows count of configured variables
   - In verbose mode, displays each variable's value and source

#### Exit Codes

- `0`: All checks passed (or warnings only)
- `1`: One or more checks failed

#### When to Use

- Before running other commands to verify connectivity
- When troubleshooting connection issues
- After changing configuration to verify settings
- As a quick diagnostic tool

#### Example Output

```
━━━ Health Check ━━━

Checking verifier connectivity...
URL: https://cartha-verifier-826542474079.us-central1.run.app
✓ Verifier is reachable (245ms)

Checking Bittensor network...
Network: finney, NetUID: 35
✓ Bittensor network is reachable (1234ms, block: 5991234)

Checking configuration...
✓ Configuration is valid

━━━ Summary ━━━
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ifier URL is not set
    elif not settings.verifier_url.startswith(("http://", "https://")):
        config_issues.append("Verifier URL must start with http:// or https://")
    
    if not settings.network:
        config_issues.append("Network is not set")
    
    if settings.netuid <= 0:
        config_issues.append(f"Invalid netuid: {settings.netuid}")
    
    if config_issues:
        console.print(f"[bold yellow]⚠ Configuration issues found[/]:")
        for issue in config_issues:
            console.print(f"  • {issue}")
        checks_warning += 1
        config_status = "Issues found"
    else:
        console.print("[bold green]✓ Configuration is valid[/]")
        checks_passed += 1
        config_status = "Valid"
    
    results.append({
        "name": "Configuration",
        "status": "pass" if not config_issues else "warning",
        "details": config_status,
        "issues": config_issues if config_issues else None,
    })
    
    # Summary
    console.print()
    console.print("[bold cyan]━━━ Summary ━━━[/]")
    
    summary_table = Table(show_header=True, header_style="bold cyan")
    summary_table.add_column("Check", style="cyan")
    summary_table.add_column("Status", justify="center")
    summary_table.add_column("Details", style="dim")
    summary_table.add_column("Latency", justify="right", style="dim")
    
    for result in results:
        status_icon = {
            "pass": "[bold green]✓[/]",
            "warning": "[bold yellow]⚠[/]",
            "fail": "[bold red]✗[/]",
        }.get(result["status"], "?")
        
        latency_str = f"{result['latency_ms']}ms" if result.get("latency_ms") else "-"
        details = result["details"]
        if result.get("issues"):
            details += f" ({len(result['issues'])} issue(s))"
        
        summary_table.add_row(
            result["name"],
            status_icon,
            details,
            latency_str,
        )
    
    console.print(summary_table)
    console.print()
    
    # Overall status
    total_checks = checks_passed + checks_failed + checks_warning
    if checks_failed == 0 and checks_warning == 0:
        console.print("[bold green]✓ All checks passed![/] CLI is ready to use.")
        raise typer.Exit(code=0)
    elif checks_failed == 0:
        console.print(
            f"[bold yellow]⚠ {checks_warning} warning(s) found[/], but CLI should work. "
            "Review configuration if needed."
        )
        raise typer.Exit(code=0)
    else:
        console.print(
            f"[bold red]✗ {checks_failed} check(s) failed[/], {checks_warning} warning(s). "
            "Please fix issues before using the CLI."
        )
        if verbose:
            console.print("\n[bold]Troubleshooting:[/]")
            console.print("• Check your network connectivity")
            console.print(f"• Verify verifier URL: {settings.verifier_url}")
            console.print(f"• Verify Bittensor network: {settings.network}")
            console.print("• Check environment variables: CARTHA_VERIFIER_URL, CARTHA_NETWORK, CARTHA_NETUID")
        raise typer.Exit(code=1)

### cartha pair status *(Legacy)*

Legacy command for checking pair status. **Deprecated** - use `cartha miner status` instead for faster, unauthenticated status checks.

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
| `CARTHA_LOCK_UI_URL` | Cartha Lock UI frontend URL | `https://cartha.finance` |
| `CARTHA_BASE_SEPOLIA_RPC` | Base Sepolia RPC endpoint for approval detection (optional) | `None` (uses public endpoint) |
| `CARTHA_EVM_PK` | EVM private key for local signing (optional) | - |
| `CARTHA_RETRY_MAX_ATTEMPTS` | Maximum number of retry attempts for failed requests | `3` |
| `CARTHA_RETRY_BACKOFF_FACTOR` | Exponential backoff multiplier between retries | `1.5` |
| `BITTENSOR_WALLET_PATH` | Override wallet path if keys are not in the default location | - |

### Setting Environment Variables

The easiest way to manage environment variables is using the `cartha utils config` command:

```bash
# View all available variables and their descriptions
cartha utils config

# Set a variable (writes to .env file)
cartha utils config set CARTHA_VERIFIER_URL https://cartha-verifier-826542474079.us-central1.run.app
cartha utils config set CARTHA_NETWORK finney
cartha utils config set CARTHA_NETUID 35

# Get information about a specific variable
cartha utils config get CARTHA_VERIFIER_URL

# Remove a variable
cartha utils config unset CARTHA_EVM_PK
```

**Alternative methods:**

```bash
# Linux/macOS - export in shell
export CARTHA_VERIFIER_URL="https://cartha-verifier-826542474079.us-central1.run.app"
export CARTHA_NETWORK="finney"
export CARTHA_NETUID="35"

# Windows (PowerShell)
$env:CARTHA_VERIFIER_URL="https://cartha-verifier-826542474079.us-central1.run.app"
$env:CARTHA_NETWORK="finney"
$env:CARTHA_NETUID="35"

# Manual .env file (create in project root)
CARTHA_VERIFIER_URL=https://cartha-verifier-826542474079.us-central1.run.app
CARTHA_NETWORK=finney
CARTHA_NETUID=35
CARTHA_RETRY_MAX_ATTEMPTS=3
CARTHA_RETRY_BACKOFF_FACTOR=1.5
```

### Retry Logic

The CLI automatically retries failed requests to improve reliability:

- **Automatic Retries**: Failed requests are automatically retried up to 3 times (configurable)
- **Exponential Backoff**: Wait time between retries increases exponentially (1.5x multiplier)
- **Retry Conditions**: Retries occur for:
  - Network timeouts
  - Connection errors
  - HTTP 5xx server errors (500, 502, 503, 504)
- **Non-Retryable**: 4xx client errors (400, 401, 403, 404) are not retried

**Example**: With default settings, retry delays are:
- Attempt 1: Immediate
- Attempt 2: Wait 1.5 seconds
- Attempt 3: Wait 2.25 seconds

You can customize retry behavior via environment variables:
```bash
export CARTHA_RETRY_MAX_ATTEMPTS=5
export CARTHA_RETRY_BACKOFF_FACTOR=2.0
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

3. **Configure environment variables (optional):**
   ```bash
   cartha utils config
   cartha utils config set CARTHA_NETWORK finney
   ```
   See available configuration options and set them as needed.

### Creating a Lock Position

1. **Start the lock flow:**
   ```bash
   cartha vault lock \
     --coldkey my-coldkey \
     --hotkey my-hotkey \
     --pool-id BTCUSD \
     --amount 250.0 \
     --lock-days 30 \
     --owner-evm 0xYourEVMAddress \
     --chain-id 8453 \
     --vault-address 0xVaultAddress
   ```

2. **The CLI automatically opens the Cartha Lock UI** in your browser with all parameters pre-filled

3. **Connect your wallet** (MetaMask, Coinbase Wallet, Talisman, or WalletConnect) - make sure it matches the `--owner-evm` address

4. **Phase 1 - Approve USDC**: The frontend guides you through approving USDC spending. The CLI automatically detects when approval completes

5. **Phase 2 - Lock Position**: The frontend guides you through locking your USDC in the vault contract

6. **Wait for auto-detection** - The verifier will automatically detect your `LockCreated` event and add you to the upcoming epoch

**⚠️ Important:** 
- Make sure the wallet you connect in the frontend matches the `--owner-evm` address specified in the CLI
- The frontend includes wallet validation to prevent using the wrong address
- If you request a new signature after already requesting one, make sure to use the **newest signature only**. Using an old signature will lock your funds but won't credit your miner automatically. In this case, open a support ticket on Discord for manual recovery. You'll need to provide:
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

2. **Use the Cartha Lock UI to extend or top up:**
   - Visit the Cartha Lock UI: https://cartha.finance/manage
   - Navigate to "My Positions" to view your existing locks
   - Click "Extend" or "Top Up" buttons for the position you want to modify
   - Follow the on-screen instructions to complete the transaction
   - The verifier automatically detects `LockUpdated` events
   - Your updated amount/lock_days will be reflected in `miner status` within 30 seconds

**Note**: Extend Lock and Top Up features are currently in testing and may not work properly yet. If you encounter issues, contact support on Discord.

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

### Configuration Issues

Use the config command to view and set environment variables:

```bash
# View all configuration options
cartha utils config

# Set a specific variable
cartha utils config set CARTHA_VERIFIER_URL https://your-verifier-url.com
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

| Feature | `miner status` | `pair status` (legacy) |
| --- | --- | --- |
| Authentication | ❌ Not required | ✅ Required |
| Speed | ⚡ Fast | 🐌 Slower |
| Password Display | ❌ Never | ✅ Yes |
| Pool Information | ✅ Yes | ✅ Yes |
| Expiration Warnings | ✅ Yes | ✅ Yes |
| Recommended | ✅ Yes | ❌ Deprecated |

**Recommendation:** Use `cartha miner status` for all status checks. The legacy `pair status` command is deprecated.

---

For more help, see [Feedback & Support](FEEDBACK.md).
