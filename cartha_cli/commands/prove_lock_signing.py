"""External signing helpers for prove-lock command."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import typer
from web3 import Web3

from ..eth712 import LockProofMessage
from ..utils import normalize_hex
from .common import console


def generate_external_signing_files(
    chain: int,
    vault: str,
    miner_evm: str,
    hotkey: str,
    slot: int,
    tx: str,
    amount_base_units: int,
    password: str,
    timestamp: int,
) -> tuple[Path, Path, Path]:
    """Generate EIP-712 signing files for external signing.

    Returns tuple of (json_filename, txt_filename, html_filename)
    """
    # Build EIP-712 message structure (without lockDays - read from on-chain event)
    eip712_message = LockProofMessage(
        chain_id=chain,
        vault_address=Web3.to_checksum_address(vault),
        miner_evm_address=miner_evm,
        miner_hotkey=hotkey,
        slot_uid=str(slot),
        tx_hash=tx.lower(),
        amount=amount_base_units,
        password=password.lower(),
        timestamp=timestamp,
    )
    typed_data = eip712_message.to_eip712()

    # Convert HexBytes to strings for JSON serialization
    def hexbytes_to_str(obj: Any) -> str:
        """Convert HexBytes to hex string for JSON serialization."""
        from hexbytes import HexBytes

        if isinstance(obj, HexBytes):
            return obj.hex()
        raise TypeError(
            f"Object of type {type(obj)} is not JSON serializable"
        )

    # Serialize to JSON with HexBytes conversion
    json_str = json.dumps(typed_data, default=hexbytes_to_str, indent=2)

    # Create output directory if it doesn't exist
    output_dir = Path.cwd() / "cartha_eip712_outputs"
    output_dir.mkdir(exist_ok=True)

    # Generate filename with timestamp
    timestamp_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    json_filename = output_dir / f"eip712_message_{timestamp_str}.json"
    txt_filename = output_dir / f"eip712_instructions_{timestamp_str}.txt"

    # Save JSON file (ready to use with MetaMask, ethers.js, etc.)
    with open(json_filename, "w") as f:
        f.write(json_str)

    # Create simple HTML file for easy signing
    html_filename = output_dir / f"eip712_signer_{timestamp_str}.html"
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Cartha EIP-712 Signer</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
        }}
        .info {{
            background: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #2196F3;
        }}
        .warning {{
            background: #fff3cd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #ffc107;
        }}
        button {{
            background: #4CAF50;
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            margin: 10px 5px;
        }}
        button:hover {{
            background: #45a049;
        }}
        button:disabled {{
            background: #ccc;
            cursor: not-allowed;
        }}
        #signature {{
            margin-top: 20px;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 5px;
            word-break: break-all;
            font-family: monospace;
            display: none;
        }}
        .success {{
            color: #4CAF50;
            font-weight: bold;
        }}
        .error {{
            color: #f44336;
            font-weight: bold;
        }}
        label {{
            display: block;
            margin: 15px 0 5px 0;
            font-weight: bold;
        }}
        input[type="text"] {{
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Cartha EIP-712 LockProof Signer</h1>
        
        <div class="info">
            <strong>Instructions:</strong><br>
            1. Make sure MetaMask is installed and connected to Chain ID {chain}<br>
            2. Ensure you're using account: <strong>{miner_evm}</strong><br>
            3. Click "Load JSON" to load the message file<br>
            4. Click "Sign Message" - MetaMask will pop up<br>
            5. Review and sign in MetaMask<br>
            6. Copy the signature below and paste it in the CLI
        </div>
        
        <div class="warning">
            <strong>⚠️ Important:</strong> This tool signs EIP-712 typed data, not plain text.
            Etherscan's "Sign Message" won't work - you must use this tool or the console method.
        </div>
        
        <div id="fileProtocolWarning" style="display:none; background: #ffebee; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #f44336;">
            <strong>⚠️ File Protocol Detected:</strong><br>
            MetaMask cannot be accessed from file:// URLs. You need to serve this file via HTTP.<br><br>
            <strong>Quick Fix:</strong><br>
            1. Open terminal in the folder containing this HTML file<br>
            2. Run: <code>python3 -m http.server 8000</code><br>
            3. Open: <a href="#" id="localServerLink" onclick="return false;">http://localhost:8000/{html_filename.name}</a><br><br>
            Or use the browser console method from the instructions file.
        </div>
        
        <button onclick="connectWallet()" style="background: #2196F3; margin-bottom: 20px;">Connect Wallet</button>
        
        <div style="margin-top: 20px;">
            <label for="jsonPaste"><strong>Option 1: Paste JSON Content</strong></label>
            <textarea id="jsonPaste" placeholder='Paste the entire JSON file contents here, e.g.:
{{
  "domain": {{
    "name": "CarthaLockProof",
    ...
  }},
  ...
}}' style="width: 100%; min-height: 200px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-family: monospace; font-size: 12px; box-sizing: border-box;"></textarea>
            <button onclick="signFromPaste()" style="margin-top: 10px;">Sign from Pasted JSON</button>
        </div>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 2px solid #ddd;">
            <label for="jsonUpload"><strong>Option 2: Upload JSON File</strong></label>
            <input type="file" id="jsonUpload" accept=".json,application/json" style="margin-top: 5px;">
            <button onclick="signFromUpload()" style="margin-top: 10px;">Sign from Uploaded File</button>
        </div>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 2px solid #ddd;">
            <label for="jsonFile"><strong>Option 3: Load from File Path</strong></label>
            <input type="text" id="jsonFile" value="{json_filename.name}" placeholder="Enter path to JSON file" style="margin-top: 5px;">
            <button onclick="loadAndSign()" style="margin-top: 10px;">Load & Sign from Path</button>
        </div>
        
        <button onclick="copySignature()" id="copyBtn" disabled style="margin-top: 20px;">Copy Signature</button>
        
        <div id="signature">
            <h3 class="success">✓ Signature Generated:</h3>
            <p id="sigText"></p>
            <p><strong>Copy this signature and paste it in the CLI when prompted.</strong></p>
        </div>
        
        <div id="error" style="display:none; margin-top:20px; padding:15px; background:#ffebee; border-radius:5px;">
            <h3 class="error">❌ Error:</h3>
            <p id="errorText"></p>
        </div>
    </div>

    <script>
        let currentSignature = '';
        let currentAccount = '';
        const expectedAccount = '{miner_evm}'.toLowerCase();
        
        function getEthereumProvider() {{
            // Check for MetaMask or other injected providers
            if (typeof window.ethereum !== 'undefined') {{
                return window.ethereum;
            }}
            // Check for legacy providers
            if (typeof window.web3 !== 'undefined' && window.web3.currentProvider) {{
                return window.web3.currentProvider;
            }}
            // Check if we're on file:// protocol (MetaMask doesn't inject in file://)
            if (window.location.protocol === 'file:') {{
                // Try to detect if MetaMask is installed by checking for the extension
                // Note: This won't work, but we'll show a helpful error
                return null;
            }}
            return null;
        }}
        
        function checkIfFileProtocol() {{
            return window.location.protocol === 'file:';
        }}
        
        async function connectWallet() {{
            // Check if we're on file:// protocol
            if (checkIfFileProtocol()) {{
                const useServer = confirm(
                    '⚠️ MetaMask cannot be accessed from file:// URLs for security reasons.\\n\\n' +
                    'You have two options:\\n\\n' +
                    'Option 1: Use a local HTTP server (Recommended)\\n' +
                    '  - Open terminal in this folder\\n' +
                    '  - Run: python3 -m http.server 8000\\n' +
                    '  - Then open: http://localhost:8000/' + '{html_filename.name}' + '\\n\\n' +
                    'Option 2: Use browser console method instead\\n\\n' +
                    'Click OK to see console instructions, or Cancel to try anyway.'
                );
                if (useServer) {{
                    document.getElementById('errorText').innerHTML = 
                        '<strong>To use this HTML tool with MetaMask:</strong><br><br>' +
                        '1. Open terminal in the folder containing this HTML file<br>' +
                        '2. Run: <code>python3 -m http.server 8000</code><br>' +
                        '3. Open in browser: <a href="http://localhost:8000/' + '{html_filename.name}' + '" target="_blank">http://localhost:8000/' + '{html_filename.name}' + '</a><br><br>' +
                        'Or use the browser console method from the instructions file.';
                    document.getElementById('error').style.display = 'block';
                    return;
                }}
            }}
            
            const provider = getEthereumProvider();
            if (!provider) {{
                if (checkIfFileProtocol()) {{
                    alert('MetaMask cannot be accessed from file:// URLs.\\n\\nPlease use a local HTTP server (see instructions) or use the browser console method.');
                }} else {{
                    alert('MetaMask or other Web3 wallet not found. Please install MetaMask.');
                }}
                return;
            }}
            
            try {{
                const accounts = await provider.request({{ method: 'eth_requestAccounts' }});
                if (accounts && accounts.length > 0) {{
                    currentAccount = accounts[0];
                    alert('Connected: ' + currentAccount);
                }} else {{
                    alert('No accounts found. Please unlock your wallet.');
                }}
            }} catch (error) {{
                alert('Connection error: ' + error.message);
            }}
        }}
        
        async function signMessage(message) {{
            // Check if we're on file:// protocol
            if (checkIfFileProtocol()) {{
                throw new Error(
                    'MetaMask cannot be accessed from file:// URLs.\\n\\n' +
                    'Please use a local HTTP server:\\n' +
                    '1. Open terminal in this folder\\n' +
                    '2. Run: python3 -m http.server 8000\\n' +
                    '3. Open: http://localhost:8000/' + '{html_filename.name}' + '\\n\\n' +
                    'Or use the browser console method from the instructions file.'
                );
            }}
            
            const provider = getEthereumProvider();
            if (!provider) {{
                throw new Error('MetaMask or other Web3 wallet not found. Please install MetaMask.');
            }}
            
            // Get current account
            const accounts = await provider.request({{ method: 'eth_requestAccounts' }});
            if (!accounts || accounts.length === 0) {{
                throw new Error('No wallet connected. Please connect your wallet first.');
            }}
            
            const signerAddress = accounts[0];
            currentAccount = signerAddress;
            
            // Verify correct account (warn but don't block)
            if (signerAddress.toLowerCase() !== expectedAccount) {{
                const proceed = confirm(`Warning: You're using account ${{signerAddress}}\\nExpected: {miner_evm}\\n\\nDo you want to proceed anyway?`);
                if (!proceed) {{
                    throw new Error('Signing cancelled. Please switch to the correct account.');
                }}
            }}
            
            // Sign with MetaMask
            const signature = await provider.request({{
                method: 'eth_signTypedData_v4',
                params: [signerAddress, message]
            }});
            
            return signature;
        }}
        
        async function loadAndSign() {{
            const jsonFile = document.getElementById('jsonFile').value;
            const errorDiv = document.getElementById('error');
            const signatureDiv = document.getElementById('signature');
            const copyBtn = document.getElementById('copyBtn');
            
            errorDiv.style.display = 'none';
            signatureDiv.style.display = 'none';
            copyBtn.disabled = true;
            
            try {{
                // Try to load JSON file
                let message;
                try {{
                    // Try fetching as file (works if served via HTTP)
                    const response = await fetch(jsonFile);
                    if (response.ok) {{
                        message = await response.json();
                    }} else {{
                        throw new Error('Could not load file via fetch');
                    }}
                }} catch (e) {{
                    // Fallback: prompt user to paste JSON
                    const jsonText = prompt('Could not load file automatically. Please paste the entire contents of ' + jsonFile + ':', '');
                    if (!jsonText) {{
                        throw new Error('No JSON provided');
                    }}
                    message = JSON.parse(jsonText);
                }}
                
                const signature = await signMessage(message);
                
                // Display signature
                currentSignature = signature;
                document.getElementById('sigText').textContent = signature;
                signatureDiv.style.display = 'block';
                copyBtn.disabled = false;
                
            }} catch (error) {{
                document.getElementById('errorText').textContent = error.message;
                errorDiv.style.display = 'block';
            }}
        }}
        
        async function signFromPaste() {{
            const errorDiv = document.getElementById('error');
            const signatureDiv = document.getElementById('signature');
            const copyBtn = document.getElementById('copyBtn');
            
            errorDiv.style.display = 'none';
            signatureDiv.style.display = 'none';
            copyBtn.disabled = true;
            
            try {{
                const jsonText = document.getElementById('jsonPaste').value.trim();
                if (!jsonText) {{
                    throw new Error('Please paste the JSON content first.');
                }}
                
                const message = JSON.parse(jsonText);
                const signature = await signMessage(message);
                
                currentSignature = signature;
                document.getElementById('sigText').textContent = signature;
                signatureDiv.style.display = 'block';
                copyBtn.disabled = false;
                
            }} catch (error) {{
                document.getElementById('errorText').textContent = error.message;
                errorDiv.style.display = 'block';
            }}
        }}
        
        async function signFromUpload() {{
            const errorDiv = document.getElementById('error');
            const signatureDiv = document.getElementById('signature');
            const copyBtn = document.getElementById('copyBtn');
            
            errorDiv.style.display = 'none';
            signatureDiv.style.display = 'none';
            copyBtn.disabled = true;
            
            try {{
                const fileInput = document.getElementById('jsonUpload');
                const file = fileInput.files[0];
                if (!file) {{
                    throw new Error('Please select a JSON file first.');
                }}
                
                const fileText = await file.text();
                const message = JSON.parse(fileText);
                const signature = await signMessage(message);
                
                currentSignature = signature;
                document.getElementById('sigText').textContent = signature;
                signatureDiv.style.display = 'block';
                copyBtn.disabled = false;
                
            }} catch (error) {{
                document.getElementById('errorText').textContent = error.message;
                errorDiv.style.display = 'block';
            }}
        }}
        
        function copySignature() {{
            navigator.clipboard.writeText(currentSignature).then(() => {{
                alert('Signature copied to clipboard!\\n\\nPaste it in the CLI when prompted.');
            }}).catch(err => {{
                alert('Failed to copy. Please manually copy the signature above.');
            }});
        }}
        
        // Check if file:// protocol on page load and show warning
        window.addEventListener('load', () => {{
            if (window.location.protocol === 'file:') {{
                document.getElementById('fileProtocolWarning').style.display = 'block';
                const link = document.getElementById('localServerLink');
                if (link) {{
                    link.href = 'http://localhost:8000/{html_filename.name}';
                    link.onclick = function() {{ 
                        window.open(this.href, '_blank'); 
                        return false; 
                    }};
                }}
            }}
        }});
    </script>
</body>
</html>
"""
    with open(html_filename, "w") as f:
        f.write(html_content)

    # Create human-readable instructions file
    human_amount = Decimal(amount_base_units) / Decimal(10**6)
    amount_str = f"{human_amount:.6f}".rstrip("0").rstrip(".")

    instructions = f"""EIP-712 LockProof Signing Instructions
Generated: {datetime.now(UTC).isoformat()}

⚠️  CRITICAL: You MUST use the JSON file ({json_filename.name}) - do NOT copy values from this text file.
The JSON file contains the exact format needed for signing. This text file is for reference only.

NOTE: lockDays is NOT included in the signature - it's read from the on-chain LockCreated event.

=== ⚠️ IMPORTANT: About Etherscan's "Sign Message" ===

Etherscan's "Sign Message" button uses eth_sign (plain text signing), NOT EIP-712 typed data signing.
If you paste the JSON into Etherscan's message box and sign it, the signature will be REJECTED.

However, Ledger hardware wallets DO support EIP-712 signing natively. Ledger users should use one of the methods below.

=== Option 1: Use the HTML Signer Tool (EASIEST - RECOMMENDED) ===

Works with: MetaMask, MetaMask + Ledger, MetaMask + Trezor, and other Web3 wallets

A simple HTML file has been created for you: {html_filename.name}

1. Double-click {html_filename.name} to open it in your browser
   - Or right-click → "Open with" → your browser

2. Connect your wallet:
   - If using MetaMask: Make sure MetaMask is installed and connected to Chain ID {chain}
   - If using Ledger via MetaMask: Connect Ledger to MetaMask first, then use the HTML tool
   - Ensure you're using the account: {miner_evm}
   - This MUST be the address that made the deposit

3. In the HTML page:
   - The JSON file path should already be filled in
   - Click "Load JSON & Sign Message"
   - Your wallet will pop up - review the message details and approve
   - For Ledger: You'll see the message details on your Ledger device - verify and approve
   - Copy the signature from the page
   - Paste it in the CLI when prompted

That's it! No developer console needed. Works perfectly with Ledger hardware wallets.

=== Option 2: Browser Console Method ===

Works with: MetaMask, MetaMask + Ledger, and other Web3 wallets

If the HTML tool doesn't work, use this:

1. Connect your wallet:
   - MetaMask: Make sure it's installed and connected to Chain ID {chain}
   - Ledger via MetaMask: Connect Ledger to MetaMask first
   - Ensure you're using account: {miner_evm}

2. Open the JSON file ({json_filename.name}) in a text editor
   - Copy the ENTIRE file contents (Ctrl+A, Ctrl+C)

3. Go to any website (like https://etherscan.io/verifiedSignatures#)
   - Connect your wallet if needed
   - Note: Don't use Etherscan's "Sign Message" button - use the console method below

4. Open browser console (F12 → Console tab) and paste:

   const jsonContent = `PASTE_ENTIRE_JSON_FILE_HERE`;
   const message = JSON.parse(jsonContent);
   const accounts = await window.ethereum.request({{ method: 'eth_requestAccounts' }});
   const signerAddress = accounts[0];
   if (signerAddress.toLowerCase() !== "{miner_evm}".toLowerCase()) {{
     alert("ERROR: Switch to account {miner_evm}");
   }} else {{
     const signature = await window.ethereum.request({{
       method: "eth_signTypedData_v4",
       params: [signerAddress, message]
     }});
     console.log("Signature:", signature);
     alert("Copy: " + signature);
   }}

5. Replace `PASTE_ENTIRE_JSON_FILE_HERE` with your JSON content
6. Your wallet will pop up - approve the signature
   - For Ledger: You'll see the message on your device - verify and approve
7. Copy the signature and paste in CLI

=== For Ledger Users Specifically ===

Ledger hardware wallets natively support EIP-712 signing. You can:

1. **Via MetaMask + Ledger** (Recommended):
   - Connect your Ledger to MetaMask
   - Use Option 1 (HTML tool) or Option 2 (console method) above
   - Your Ledger will display the message details for verification
   - Approve on your Ledger device

2. **Via Ledger Live** (if supported):
   - Some dApps support EIP-712 signing directly through Ledger Live
   - Check if your preferred dApp/wallet interface supports EIP-712

3. **Important Notes for Ledger**:
   - Always verify the message details shown on your Ledger screen
   - Make sure the chainId matches {chain}
   - Verify the minerEvmAddress matches {miner_evm}
   - The signature will be valid EIP-712 format (not plain text)

=== Option 3: Using ethers.js (Advanced) ===

const {{ ethers }} = require("ethers");
const fs = require('fs');
const message = JSON.parse(fs.readFileSync('{json_filename.name}', 'utf8'));
const provider = new ethers.providers.Web3Provider(window.ethereum);
const signer = provider.getSigner();
const signature = await signer._signTypedData(message.domain, message.types, message.message);
console.log("Signature:", signature);

=== After Signing (All Methods) ===
1. Copy the signature (starts with 0x, 132 characters total: 0x + 130 hex chars)
2. Return to the CLI terminal
3. Paste the signature when prompted

=== Troubleshooting ===

Problem: "Invalid signature" error
Solution: 
  - Make sure you used the JSON file, not values from this text file
  - Verify all JSON syntax is correct (check for missing commas, brackets)
  - Ensure the JSON was copied completely

Problem: MetaMask shows wrong chain
Solution:
  - Switch MetaMask to Chain ID {chain}
  - Refresh the page and try again

Problem: "Address mismatch" error  
Solution:
  - The signature must come from EVM address: {miner_evm}
  - Switch to the correct account in MetaMask

Problem: Signature format error
Solution:
  - Make sure you're using `eth_signTypedData_v4` (not v3 or eth_sign)
  - Verify the message object structure matches the JSON file exactly

=== Security Reminders ===
- Never share your private key or pair password
- Always review the message details in MetaMask's signing popup before confirming
- The signature cryptographically proves you control the EVM address that made the deposit
- Double-check all values match your deposit transaction before signing
"""

    with open(txt_filename, "w") as f:
        f.write(instructions)

    return json_filename, txt_filename, html_filename


def collect_external_signature() -> str:
    """Collect signature from user after external signing."""
    console.print("\n[bold yellow]Next steps:[/]")
    console.print("1. Open the JSON file and copy its contents")
    console.print(
        "2. Use Etherscan Verified Signatures (https://etherscan.io/verifiedSignatures#),"
    )
    console.print(
        "   MetaMask browser console, ethers.js, or another EIP-712 compatible tool to sign"
    )
    console.print("3. Copy the signature (0x + 130 hex characters)")
    console.print("4. Return here and paste the signature when prompted")
    console.print(
        "\n[dim]Tip:[/] The JSON file is formatted exactly as needed - copy it as-is without modifications."
    )
    console.print(
        "\n[bold cyan]Press Enter when you have your signature ready...[/]"
    )
    input()  # Wait for user to press Enter

    while True:
        signature = typer.prompt(
            "Paste your EIP-712 signature (0x...)", show_default=False
        )
        signature_normalized = normalize_hex(signature)
        # EIP-712 signature is 65 bytes = 0x + 130 hex chars
        if len(signature_normalized) == 132:
            return signature_normalized
        console.print(
            "[bold red]Error:[/] Signature must be 65 bytes (0x + 130 hex characters)"
        )

