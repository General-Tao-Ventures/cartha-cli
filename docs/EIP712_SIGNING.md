# EIP-712 LockProof Signing Guide

This guide explains how to sign EIP-712 LockProof messages for the Cartha subnet. Miners must sign a LockProof message to link their EVM wallet deposits to their Bittensor hotkey.

**Important:** `lockDays` is NOT included in the LockProof schema—it is always read from the on-chain `LockCreated` event emitted by the vault contract.

## What is EIP-712?

EIP-712 is a standard for signing structured data (typed data) in Ethereum. Instead of signing raw bytes, EIP-712 allows wallets to display human-readable information about what you're signing, making it safer and more user-friendly.

## Why Do Miners Need to Sign?

The EIP-712 signature cryptographically proves:
1. **EVM Ownership**: You control the EVM wallet that made the deposit
2. **Identity Linking**: Links your EVM wallet ↔ Bittensor hotkey/slot
3. **Transaction Binding**: Ties the proof to a specific on-chain transaction
4. **Integrity**: Ensures amount, vault address, and pair password match what was signed
5. **Replay Protection**: Timestamp prevents reuse of old proofs

## Prerequisites

Before signing, you need:

- **Chain ID**: The EVM chain where you deposited (Base = 8453, Ethereum = 1)
- **Vault Address**: The vault contract address where you locked USDC
- **Transaction Hash**: The `txHash` of your deposit transaction
- **Amount**: The USDC amount you locked (in base units or normalized)
- **Hotkey**: Your Bittensor hotkey (SS58 format, e.g., `bt1...`)
- **Slot UID**: Your subnet slot UID (from registration)
- **Pair Password**: The pair password from the verifier (0x-prefixed hex, 32 bytes)
- **EVM Private Key**: Only needed if signing locally (keep this secure!)

## Method 1: Local CLI Signing (Recommended for Testing)

If you have your EVM private key and want to sign directly in the CLI:

### Step 1: Set Environment Variable (Optional)

```bash
export CARTHA_EVM_PK="0x..."  # Your EVM private key
```

**Security Note**: Never commit private keys to git or share them publicly. Consider using a `.env` file (add it to `.gitignore`).

### Step 2: Run `prove-lock` Command

```bash
uv run cartha prove-lock \
  --chain 8453 \
  --vault 0x... \
  --tx 0x... \
  --amount 250 \
  --hotkey bt1... \
  --slot 123 \
  --pwd 0x...
```

When prompted:
- "Do you already have an EIP-712 signature? (y/n)" → **n**
- "Sign locally with private key? (y/n)" → **y**
- If `CARTHA_EVM_PK` is not set, you'll be prompted securely (input is hidden)

The CLI will:
1. Derive your EVM address from the private key automatically
2. Generate a timestamp
3. Build the EIP-712 message
4. Sign it with your private key
5. Submit the proof to the verifier

### Advantages

- ✅ Fast and convenient
- ✅ No external tools needed
- ✅ Integrated into CLI workflow

### Disadvantages

- ⚠️ Requires exposing private key (even if only in memory)
- ⚠️ Not suitable for hardware wallets
- ⚠️ Less secure than external wallet signing

## Method 2: External Wallet Signing (Recommended for Production)

For better security, especially with hardware wallets, sign externally using MetaMask, ethers.js, or another EIP-712-compatible wallet.

### Step 1: Get Message Structure

Run `prove-lock` without a signature:

```bash
uv run cartha prove-lock \
  --chain 8453 \
  --vault 0x... \
  --tx 0x... \
  --amount 250 \
  --hotkey bt1... \
  --slot 123 \
  --pwd 0x...
```

When prompted:
- "Do you already have an EIP-712 signature? (y/n)" → **n**
- "Sign locally with private key? (y/n)" → **n**

The CLI will display the message structure you need to sign.

### Step 2: Sign with MetaMask

**Using MetaMask's `eth_signTypedData_v4`:**

```javascript
const message = {
  domain: {
    name: "CarthaLockProof",
    version: "1",
    chainId: 8453  // Base mainnet
  },
  types: {
    EIP712Domain: [
      { name: "name", type: "string" },
      { name: "version", type: "string" },
      { name: "chainId", type: "uint256" }
    ],
    LockProof: [
      { name: "vaultAddress", type: "address" },
      { name: "minerEvmAddress", type: "address" },
      { name: "minerHotkey", type: "string" },
      { name: "slotUID", type: "string" },
      { name: "chainId", type: "uint256" },
      { name: "txHash", type: "bytes32" },
      { name: "amount", type: "uint256" },
      { name: "pwd", type: "bytes32" },
      { name: "timestamp", type: "uint256" }
    ]
  },
  primaryType: "LockProof",
  message: {
    vaultAddress: "0x...",
    minerEvmAddress: "0x...",  // Your EVM address
    minerHotkey: "bt1...",
    slotUID: "123",
    chainId: 8453,
    txHash: "0x...",
    amount: 250000000,  // Base units (6 decimals)
    pwd: "0x...",  // Pair password
    timestamp: 1234567890  // Unix timestamp
  }
};

// Sign with MetaMask
const signature = await window.ethereum.request({
  method: "eth_signTypedData_v4",
  params: [account, JSON.stringify(message)]
});
```

### Step 3: Sign with ethers.js

```javascript
const { ethers } = require("ethers");

const provider = new ethers.providers.Web3Provider(window.ethereum);
const signer = provider.getSigner();

const domain = {
  name: "CarthaLockProof",
  version: "1",
  chainId: 8453
};

const types = {
  LockProof: [
    { name: "vaultAddress", type: "address" },
    { name: "minerEvmAddress", type: "address" },
    { name: "minerHotkey", type: "string" },
    { name: "slotUID", type: "string" },
    { name: "chainId", type: "uint256" },
    { name: "txHash", type: "bytes32" },
    { name: "amount", type: "uint256" },
    { name: "pwd", type: "bytes32" },
    { name: "timestamp", type: "uint256" }
  ]
};

const message = {
  vaultAddress: "0x...",
  minerEvmAddress: "0x...",
  minerHotkey: "bt1...",
  slotUID: "123",
  chainId: 8453,
  txHash: "0x...",
  amount: 250000000,
  pwd: "0x...",
  timestamp: 1234567890
};

const signature = await signer._signTypedData(domain, types, message);
```

### Step 4: Submit Signature

After signing externally, submit the signature:

```bash
uv run cartha prove-lock \
  --chain 8453 \
  --vault 0x... \
  --tx 0x... \
  --amount 250 \
  --hotkey bt1... \
  --slot 123 \
  --miner-evm 0x... \
  --pwd 0x... \
  --signature 0x... \
  --timestamp 1234567890
```

Or when prompted:
- "Do you already have an EIP-712 signature? (y/n)" → **y**
- Paste your signature

### Advantages

- ✅ More secure (hardware wallet support)
- ✅ Private key never exposed to CLI
- ✅ Better for production use
- ✅ Works with MetaMask, Ledger, Trezor, etc.

### Disadvantages

- ⚠️ Requires external tooling
- ⚠️ More steps involved

## EIP-712 Message Structure

The complete EIP-712 message structure:

```json
{
  "domain": {
    "name": "CarthaLockProof",
    "version": "1",
    "chainId": 8453
  },
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" },
      { "name": "version", "type": "string" },
      { "name": "chainId", "type": "uint256" }
    ],
    "LockProof": [
      { "name": "vaultAddress", "type": "address" },
      { "name": "minerEvmAddress", "type": "address" },
      { "name": "minerHotkey", "type": "string" },
      { "name": "slotUID", "type": "string" },
      { "name": "chainId", "type": "uint256" },
      { "name": "txHash", "type": "bytes32" },
      { "name": "amount", "type": "uint256" },
      { "name": "pwd", "type": "bytes32" },
      { "name": "timestamp", "type": "uint256" }
    ]
  },
  "primaryType": "LockProof",
  "message": {
    "vaultAddress": "0x...",
    "minerEvmAddress": "0x...",
    "minerHotkey": "bt1...",
    "slotUID": "123",
    "chainId": 8453,
    "txHash": "0x...",
    "amount": 250000000,
    "pwd": "0x...",
    "timestamp": 1234567890
  }
}
```

### Field Descriptions

- **vaultAddress**: Vault contract address (checksummed)
- **minerEvmAddress**: Your EVM wallet address (checksummed)
- **minerHotkey**: Bittensor hotkey (SS58 format)
- **slotUID**: Subnet slot UID (string)
- **chainId**: EVM chain ID (Base = 8453, Ethereum = 1)
- **txHash**: Transaction hash of your deposit (32 bytes, 0x-prefixed)
- **amount**: USDC amount in base units (6 decimals, e.g., 250 USDC = 250000000)
- **pwd**: Pair password from verifier (32 bytes, 0x-prefixed hex)
- **timestamp**: Unix timestamp in seconds (prevents replay attacks)

## EVM Address Management

**Important**: The EVM address is **derived from your private key**, not stored separately.

- If signing locally: CLI derives address automatically from private key
- If signing externally: You must provide the EVM address that matches the signing wallet

The verifier checks that the signature was created by the owner of `minerEvmAddress`.

## Troubleshooting

### "Invalid signature"

**Possible causes:**
- Signature doesn't match the message
- Wrong EVM address provided
- Message fields don't match what was signed
- Chain ID mismatch

**Solution:**
- Verify all message fields match exactly
- Ensure you're using the correct chain ID
- Check that the EVM address matches the signing wallet

### "Password must be 32 bytes"

**Problem**: Pair password format is incorrect

**Solution**: Pair password must be exactly 32 bytes (0x + 64 hex characters)

### "Transaction hash must be 32 bytes"

**Problem**: Transaction hash format is incorrect

**Solution**: Transaction hash must be exactly 32 bytes (0x + 64 hex characters)

### "eth-account is required"

**Problem**: Missing dependency for local signing

**Solution**: Install dependencies: `uv sync` or `pip install eth-account`

### Signature from MetaMask doesn't work

**Possible causes:**
- Wrong chain ID in domain
- Message fields don't match exactly
- Using wrong signing method

**Solution:**
- Ensure `chainId` in domain matches the actual chain
- Verify all message fields match exactly (including hex formatting)
- Use `eth_signTypedData_v4` (not `eth_sign`)

## Security Best Practices

1. **Never share private keys**: Keep `CARTHA_EVM_PK` secure
2. **Use hardware wallets**: For production, prefer external wallet signing
3. **Verify message before signing**: Always check what you're signing
4. **Keep pair password secret**: Exposure allows others to steal your locked USDC
5. **Use testnet first**: Test the signing flow on testnet before mainnet

## Testnet vs Mainnet

- **Testnet**: Uses `testnet/build_lock_proof.py` script with mock data
- **Mainnet**: Requires real chain/vault/tx and real signatures

See [testnet/README.md](../testnet/README.md) for testnet-specific instructions.

## Additional Resources

- [EIP-712 Specification](https://eips.ethereum.org/EIPS/eip-712)
- [MetaMask EIP-712 Guide](https://docs.metamask.io/guide/signing-data.html)
- [ethers.js Typed Data](https://docs.ethers.io/v5/api/utils/signing-key/#utils-signTypedData)

## Getting Help

If you encounter issues:

1. Check this guide for common problems
2. Review [FEEDBACK.md](./FEEDBACK.md) for support channels
3. Open a GitHub issue with:
   - Error messages
   - Command used
   - Environment details (redact sensitive info)

