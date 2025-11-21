import json
import sys
import types
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.append(str(Path(__file__).resolve().parents[1]))


class _StubKeyFileError(Exception):
    pass


class _StubKeypair:
    def __init__(self, ss58_address: str | None = None):
        self.ss58_address = ss58_address

    def verify(
        self, message: bytes, signature: bytes
    ) -> bool:  # pragma: no cover - stub
        return True


class _StubWeb3:
    @staticmethod
    def is_address(value: str) -> bool:
        return True

    @staticmethod
    def to_checksum_address(value: str) -> str:
        return value


# Stub eth_account if not available (for tests that don't need it)
try:
    from eth_account import Account

    _eth_account_available = True
except ImportError:
    _eth_account_available = False

    # Create a minimal stub
    class _StubAccount:
        @staticmethod
        def create():
            class _StubAccountInstance:
                def __init__(self):
                    self.key = types.SimpleNamespace(hex=lambda: "0x" + "00" * 32)
                    self.address = "0x0000000000000000000000000000000000000000"

            return _StubAccountInstance()

        @staticmethod
        def from_key(key):
            class _StubAccountInstance:
                def __init__(self):
                    self.address = "0x0000000000000000000000000000000000000000"

            return _StubAccountInstance()

        @staticmethod
        def sign_message(message, private_key):
            class _StubSignedMessage:
                def __init__(self):
                    self.signature = types.SimpleNamespace(hex=lambda: "0x" + "00" * 65)

            return _StubSignedMessage()

    Account = _StubAccount

bt_stub = types.SimpleNamespace(
    KeyFileError=_StubKeyFileError,
    Keypair=_StubKeypair,
    wallet=lambda *args, **kwargs: None,
    subtensor=lambda *args, **kwargs: None,
)
sys.modules.setdefault("bittensor", bt_stub)
sys.modules.setdefault("web3", types.SimpleNamespace(Web3=_StubWeb3))
if not _eth_account_available:
    sys.modules.setdefault("eth_account", types.SimpleNamespace(Account=Account))

from cartha_cli.bt import RegistrationResult  # noqa: E402
from cartha_cli.main import app  # noqa: E402

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_register_command_success(monkeypatch):
    def fake_register_hotkey(**kwargs):
        return RegistrationResult(status="pow", success=True, uid=10, hotkey="bt1abc")

    def fake_auth_payload(**kwargs):
        return {"message": "msg", "signature": "0xdead", "expires_at": 0}

    def fake_issue(**kwargs):
        return {"pwd": "0x" + "11" * 32}

    class DummyHotkey:
        def __init__(self, ss58_address: str = "bt1abc"):
            self.ss58_address = ss58_address

        def sign(self, message: bytes) -> bytes:
            # Return a fake signature
            return b"\x00" * 64

    class DummyWallet:
        def __init__(self):
            self.hotkey = DummyHotkey("bt1abc")
            self.coldkeypub = type("Coldkey", (), {"ss58_address": "bt1cold"})()
            self.path = "~/.bittensor/wallets/"

    class DummySubtensor:
        def is_hotkey_registered(self, hotkey, netuid):
            return False

        def get_burn_cost(self, netuid):
            return 0.0005

        def get_balance(self, address):
            return 10.9941

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)
    monkeypatch.setattr("cartha_cli.pair.build_pair_auth_payload", fake_auth_payload)
    monkeypatch.setattr("cartha_cli.main.register_pair_password", fake_issue)

    def fake_get_wallet(*args, **kwargs):
        return DummyWallet()

    def fake_get_subtensor(*args, **kwargs):
        return DummySubtensor()

    # Patch bt.wallet and bt.subtensor to return our dummies
    # This is needed because get_wallet() calls bt.wallet() internally
    import bittensor as bt

    monkeypatch.setattr(bt, "wallet", lambda *args, **kwargs: DummyWallet())
    monkeypatch.setattr(bt, "subtensor", lambda *args, **kwargs: DummySubtensor())

    # Also patch the convenience functions
    monkeypatch.setattr("cartha_cli.bt.get_wallet", fake_get_wallet)
    monkeypatch.setattr("cartha_cli.main.get_wallet", fake_get_wallet)
    monkeypatch.setattr("cartha_cli.bt.get_subtensor", fake_get_subtensor)
    monkeypatch.setattr("cartha_cli.main.get_subtensor", fake_get_subtensor)
    monkeypatch.setattr("typer.confirm", lambda *args, **kwargs: True)  # Auto-confirm

    result = runner.invoke(
        app,
        [
            "register",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "bt1abc",
            "--network",
            "finney",
            "--netuid",
            "35",
        ],
    )
    assert result.exit_code == 0
    # Updated assertion to match new success message format
    assert (
        "Registered on netuid" in result.stdout
        or "Registration success" in result.stdout
    )
    assert "UID" in result.stdout or "Registered UID: 10" in result.stdout
    assert "Pair password for bt1abc/10" in result.stdout


def test_register_command_already(monkeypatch):
    def fake_register_hotkey(**kwargs):
        return RegistrationResult(
            status="already", success=True, uid=7, hotkey="bt1abc"
        )

    class DummyHotkey:
        def __init__(self, ss58_address: str = "bt1abc"):
            self.ss58_address = ss58_address

        def sign(self, message: bytes) -> bytes:
            # Return a fake signature
            return b"\x00" * 64

    class DummyWallet:
        def __init__(self):
            self.hotkey = DummyHotkey("bt1abc")
            self.coldkeypub = type("Coldkey", (), {"ss58_address": "bt1cold"})()
            self.path = "~/.bittensor/wallets/"

    class DummySubtensor:
        def is_hotkey_registered(self, hotkey, netuid):
            return True

        def get_neuron_for_pubkey_and_subnet(self, hotkey, netuid):
            return type("Neuron", (), {"is_null": False, "uid": 7})()

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)

    def fake_get_wallet(*args, **kwargs):
        return DummyWallet()

    def fake_get_subtensor(*args, **kwargs):
        return DummySubtensor()

    monkeypatch.setattr("cartha_cli.bt.get_wallet", fake_get_wallet)
    monkeypatch.setattr("cartha_cli.main.get_wallet", fake_get_wallet)
    monkeypatch.setattr("cartha_cli.bt.get_subtensor", fake_get_subtensor)
    monkeypatch.setattr("cartha_cli.main.get_subtensor", fake_get_subtensor)

    result = runner.invoke(
        app,
        [
            "register",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "bt1abc",
        ],
    )
    assert result.exit_code == 0
    assert "Hotkey already registered" in result.stdout
    assert "UID: 7" in result.stdout


def test_register_command_failure(monkeypatch):
    def fake_register_hotkey(**kwargs):
        return RegistrationResult(
            status="pow", success=False, uid=None, hotkey="bt1abc"
        )

    class DummyHotkey:
        def __init__(self, ss58_address: str = "bt1abc"):
            self.ss58_address = ss58_address

        def sign(self, message: bytes) -> bytes:
            # Return a fake signature
            return b"\x00" * 64

    class DummyWallet:
        def __init__(self):
            self.hotkey = DummyHotkey("bt1abc")
            self.coldkeypub = type("Coldkey", (), {"ss58_address": "bt1cold"})()
            self.path = "~/.bittensor/wallets/"

    class DummySubtensor:
        def is_hotkey_registered(self, hotkey, netuid):
            return False

        def get_burn_cost(self, netuid):
            return 0.0005

        def get_balance(self, address):
            return 10.9941

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)

    def fake_get_wallet(*args, **kwargs):
        return DummyWallet()

    def fake_get_subtensor(*args, **kwargs):
        return DummySubtensor()

    monkeypatch.setattr("cartha_cli.bt.get_wallet", fake_get_wallet)
    monkeypatch.setattr("cartha_cli.main.get_wallet", fake_get_wallet)
    monkeypatch.setattr("cartha_cli.bt.get_subtensor", fake_get_subtensor)
    monkeypatch.setattr("cartha_cli.main.get_subtensor", fake_get_subtensor)
    monkeypatch.setattr("typer.confirm", lambda *args, **kwargs: True)  # Auto-confirm
    result = runner.invoke(
        app,
        [
            "register",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "bt1abc",
        ],
    )
    assert result.exit_code == 1
    assert "Registration failed" in result.stdout


def test_register_command_wallet_error(monkeypatch):
    # Create a mock subtensor object
    mock_subtensor = types.SimpleNamespace()

    def fake_get_subtensor(*args, **kwargs):
        return mock_subtensor

    def fake_get_wallet(*args, **kwargs):
        # Raise KeyFileError - the exception handler in main.py catches bt.KeyFileError
        # Since main.py imports bt directly, we need to ensure bt.KeyFileError matches
        raise _StubKeyFileError("missing keyfile")

    # Mock both get_subtensor and get_wallet from the bt module (where they're imported from)
    monkeypatch.setattr("cartha_cli.bt.get_subtensor", fake_get_subtensor)
    monkeypatch.setattr("cartha_cli.bt.get_wallet", fake_get_wallet)
    # Also patch get_wallet where it's imported in main module (critical!)
    monkeypatch.setattr("cartha_cli.main.get_wallet", fake_get_wallet)
    # Patch bt.wallet to also raise KeyFileError (in case get_wallet calls it internally)
    import bittensor as bt

    monkeypatch.setattr(
        bt,
        "wallet",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            _StubKeyFileError("missing keyfile")
        ),
    )
    # Patch bt.KeyFileError in main module to match our stub exception type
    # This ensures the exception handler can catch it properly
    monkeypatch.setattr("cartha_cli.main.bt.KeyFileError", _StubKeyFileError)

    result = runner.invoke(
        app,
        [
            "register",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "bt1abc",
        ],
    )
    assert result.exit_code == 1
    # Verify the error message is present
    assert "Unable to open coldkey 'cold' hotkey 'bt1abc'" in result.stdout


def test_register_command_trace_unexpected(monkeypatch):
    def fake_register_hotkey(**kwargs):
        raise RuntimeError("boom")

    def fake_get_wallet(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)
    monkeypatch.setattr("cartha_cli.bt.get_wallet", fake_get_wallet)
    monkeypatch.setattr("cartha_cli.main.get_wallet", fake_get_wallet)
    # Also patch bt.wallet and bt.subtensor to raise RuntimeError
    import bittensor as bt

    monkeypatch.setattr(
        bt,
        "wallet",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(
        bt,
        "subtensor",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    # default: error handled without traceback
    result = runner.invoke(
        app,
        [
            "register",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "bt1abc",
        ],
    )
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    # Error now happens during wallet initialization, not during registration
    assert (
        "Registration failed unexpectedly" in result.stdout
        or "Failed to initialize wallet/subtensor" in result.stdout
    )

    traced = runner.invoke(
        app,
        [
            "--trace",
            "register",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "bt1abc",
        ],
    )
    assert traced.exit_code != 0
    assert isinstance(traced.exception, RuntimeError)


def test_pair_status_command(monkeypatch):
    def fake_auth_payload(**kwargs):
        return {"message": "msg", "signature": "0xdead", "expires_at": 0}

    def fake_request(**kwargs):
        assert kwargs["mode"] == "status"
        return {
            "state": "active",
            "has_pwd": True,
            "pwd": "0x" + "22" * 32,
            "issued_at": "2024-05-20T12:00:00Z",
        }

    class DummyWallet:
        def __init__(self, ss58: str) -> None:
            self.hotkey = type("Hotkey", (), {"ss58_address": ss58})()

    # Patch bt.wallet and bt.subtensor for build_pair_auth_payload and load_wallet
    import bittensor as bt

    monkeypatch.setattr(bt, "wallet", lambda *args, **kwargs: DummyWallet("bt1xyz"))
    monkeypatch.setattr(
        bt,
        "subtensor",
        lambda *args, **kwargs: type(
            "Subtensor",
            (),
            {
                "metagraph": lambda netuid: type(
                    "Metagraph", (), {"hotkeys": ["bt1xyz"] * 100}
                )()
            },
        )(),
    )

    # Patch build_pair_auth_payload in both pair and main modules
    monkeypatch.setattr("cartha_cli.pair.build_pair_auth_payload", fake_auth_payload)
    monkeypatch.setattr("cartha_cli.main.build_pair_auth_payload", fake_auth_payload)
    monkeypatch.setattr("cartha_cli.pair.request_pair_status_or_password", fake_request)
    monkeypatch.setattr("cartha_cli.main.request_pair_status_or_password", fake_request)
    monkeypatch.setattr(
        "cartha_cli.wallet.load_wallet",
        lambda wallet_name, wallet_hotkey, expected: DummyWallet("bt1xyz"),
    )
    monkeypatch.setattr("cartha_cli.pair.ensure_pair_registered", lambda **kwargs: None)
    # Patch get_uid_from_hotkey to return the slot from the test
    monkeypatch.setattr("cartha_cli.pair.get_uid_from_hotkey", lambda **kwargs: 42)

    result = runner.invoke(
        app,
        [
            "pair",
            "status",
            "--slot",
            "42",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "bt1xyz",
        ],
    )
    assert result.exit_code == 0
    assert "Pair Status" in result.stdout
    assert "State" in result.stdout
    assert "active" in result.stdout
    assert "Password issued" in result.stdout
    assert "yes" in result.stdout
    assert "Pair password" in result.stdout
    assert "0x22" in result.stdout
    assert "Keep it safe" in result.stdout


def test_pair_status_command_json(monkeypatch):
    def fake_auth_payload(**kwargs):
        return {"message": "msg", "signature": "0xdead", "expires_at": 0}

    def fake_request(**kwargs):
        return {
            "state": "pending",
            "has_pwd": False,
            "pwd": "0x" + "33" * 32,
            "issued_at": None,
        }

    class DummyWallet:
        def __init__(self, ss58: str) -> None:
            self.hotkey = type("Hotkey", (), {"ss58_address": ss58})()

    # Patch bt.wallet and bt.subtensor for build_pair_auth_payload and load_wallet
    import bittensor as bt

    monkeypatch.setattr(bt, "wallet", lambda *args, **kwargs: DummyWallet("bt1xyz"))
    monkeypatch.setattr(
        bt,
        "subtensor",
        lambda *args, **kwargs: type(
            "Subtensor",
            (),
            {
                "metagraph": lambda netuid: type(
                    "Metagraph", (), {"hotkeys": ["bt1xyz"] * 100}
                )()
            },
        )(),
    )

    # Patch build_pair_auth_payload in both pair and main modules
    monkeypatch.setattr("cartha_cli.pair.build_pair_auth_payload", fake_auth_payload)
    monkeypatch.setattr("cartha_cli.main.build_pair_auth_payload", fake_auth_payload)
    monkeypatch.setattr("cartha_cli.pair.request_pair_status_or_password", fake_request)
    monkeypatch.setattr("cartha_cli.main.request_pair_status_or_password", fake_request)
    monkeypatch.setattr(
        "cartha_cli.wallet.load_wallet",
        lambda wallet_name, wallet_hotkey, expected: DummyWallet("bt1xyz"),
    )
    monkeypatch.setattr("cartha_cli.pair.ensure_pair_registered", lambda **kwargs: None)
    # Patch get_uid_from_hotkey to return the slot from the test
    monkeypatch.setattr("cartha_cli.pair.get_uid_from_hotkey", lambda **kwargs: 42)

    result = runner.invoke(
        app,
        [
            "pair",
            "status",
            "--slot",
            "7",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "bt1xyz",
            "--json",
        ],
    )
    assert result.exit_code == 0
    stdout = result.stdout
    json_start = stdout.find("{")
    json_end = stdout.find("}\n", json_start)
    payload = json.loads(stdout[json_start : json_end + 1])
    assert payload["state"] == "pending"
    assert payload["hotkey"] == "bt1xyz"
    assert payload["slot"] == "7"
    assert payload["pwd"] == "0x" + "33" * 32
    assert "Keep it safe" in stdout


def test_prove_lock_command_success(monkeypatch):
    captured = {}

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    def fake_confirm(*args, **kwargs):
        # Mock Rich Confirm.ask() to return True (accept confirmation)
        return kwargs.get("default", True)

    def fake_prompt(*args, **kwargs):
        # Mock prompt for lock_days
        if "Lock period" in str(args[0]):
            return "30"  # Return default lock_days
        return "default"

    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)
    monkeypatch.setattr("rich.prompt.Confirm.ask", fake_confirm)
    monkeypatch.setattr("typer.prompt", fake_prompt)

    result = runner.invoke(
        app,
        [
            "prove-lock",
            "--chain",
            "8453",
            "--vault",
            "0x000000000000000000000000000000000000dEaD",
            "--tx",
            "0x" + "ab" * 32,
            "--amount",
            "12345",
            "--hotkey",
            "bt1xyz",
            "--slot",
            "9",
            "--miner-evm",
            "0x1111111111111111111111111111111111111111",
            "--pwd",
            "0x" + "44" * 32,
            "--signature",
            "0x" + "55" * 65,
        ],
    )

    assert result.exit_code == 0
    assert "Lock proof submitted successfully." in result.stdout
    payload = captured["payload"]
    assert payload["minerHotkey"] == "bt1xyz"
    assert payload["slotUID"] == "9"
    # Amount "12345" is < 1e9, so treated as normalized USDC and converted to base units
    assert payload["amount"] == 12345000000  # 12345 USDC = 12345 * 1e6 base units
    assert payload["pwd"] == "0x" + "44" * 32
    # lockDays should be included (default or from prompt)
    assert "lockDays" in payload
    assert 7 <= payload["lockDays"] <= 365


def test_prove_lock_with_local_signature_generation(monkeypatch):
    """Test prove-lock with local signature generation when signature is missing."""
    try:
        from eth_account import Account
    except ImportError:
        pytest.skip("eth_account not available")

    captured = {}

    # Generate a test private key and address
    test_account = Account.create()
    test_private_key = test_account.key.hex()
    test_address = test_account.address

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    # Mock environment variable
    monkeypatch.setenv("CARTHA_EVM_PK", test_private_key)
    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)

    # Mock prompts: user says they don't have signature, wants to sign locally
    prompt_responses = iter(
        [
            False,  # "Do you already have an EIP-712 signature? (y/n)" -> n
            True,  # "Sign locally with private key? (y/n)" -> y
            True,  # "Is this your correct EVM address?" -> y
            True,  # "Submit this lock proof to the verifier?" -> y
        ]
    )

    def fake_confirm(*args, **kwargs):
        return next(prompt_responses, kwargs.get("default", True))

    def fake_prompt(*args, **kwargs):
        # Mock prompt for lock_days
        if "Lock period" in str(args[0]):
            return "30"  # Return default lock_days
        return "default"

    monkeypatch.setattr("typer.confirm", fake_confirm)
    monkeypatch.setattr("rich.prompt.Confirm.ask", fake_confirm)
    monkeypatch.setattr("typer.prompt", fake_prompt)

    result = runner.invoke(
        app,
        [
            "prove-lock",
            "--chain",
            "8453",
            "--vault",
            "0x000000000000000000000000000000000000dEaD",
            "--tx",
            "0x" + "ab" * 32,
            "--amount",
            "250",
            "--hotkey",
            "bt1xyz",
            "--slot",
            "9",
            "--pwd",
            "0x" + "44" * 32,
            # No --signature flag
        ],
    )

    assert result.exit_code == 0
    assert "Lock proof submitted successfully." in result.stdout
    assert (
        "Signature generated" in result.stdout
        or "✓ Signature generated" in result.stdout
    )

    payload = captured["payload"]
    assert payload["minerHotkey"] == "bt1xyz"
    assert payload["slotUID"] == "9"
    assert payload["amount"] == 250000000  # 250 USDC = 250 * 1e6 base units
    assert payload["pwd"] == "0x" + "44" * 32
    assert "signature" in payload
    assert payload["signature"].startswith("0x")
    assert len(payload["signature"]) == 132  # 0x + 130 hex chars
    # EVM address should be derived from private key
    assert payload["minerEvmAddress"].lower() == test_address.lower()


def test_prove_lock_with_external_signature_prompt(monkeypatch):
    """Test prove-lock when user provides signature from external wallet."""
    captured = {}

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)

    # Mock prompts: user says they have signature from external wallet
    prompt_responses = iter(
        [
            True,  # "Do you already have an EIP-712 signature? (y/n)" -> y
            "0x" + "66" * 65,  # Paste signature
            "0x1111111111111111111111111111111111111111",  # EVM address
            "1234567890",  # Timestamp used when signing
            "30",  # Lock period in days
            True,  # "Submit this lock proof to the verifier?" -> y
        ]
    )

    def fake_confirm(*args, **kwargs):
        return next(prompt_responses, kwargs.get("default", True))

    def fake_prompt(*args, **kwargs):
        # Mock prompt for lock_days
        if "Lock period" in str(args[0]):
            return next(prompt_responses)
        return next(prompt_responses)

    monkeypatch.setattr("typer.confirm", fake_confirm)
    monkeypatch.setattr("typer.prompt", fake_prompt)
    monkeypatch.setattr("rich.prompt.Confirm.ask", fake_confirm)

    result = runner.invoke(
        app,
        [
            "prove-lock",
            "--chain",
            "8453",
            "--vault",
            "0x000000000000000000000000000000000000dEaD",
            "--tx",
            "0x" + "ab" * 32,
            "--amount",
            "250",
            "--hotkey",
            "bt1xyz",
            "--slot",
            "9",
            "--pwd",
            "0x" + "44" * 32,
            # No --signature flag
        ],
    )

    assert result.exit_code == 0
    assert "Lock proof submitted successfully." in result.stdout

    payload = captured["payload"]
    assert payload["minerHotkey"] == "bt1xyz"
    assert payload["slotUID"] == "9"
    assert payload["amount"] == 250000000
    assert payload["signature"] == "0x" + "66" * 65
    assert payload["minerEvmAddress"] == "0x1111111111111111111111111111111111111111"


def test_prove_lock_local_signature_without_env_var(monkeypatch):
    """Test prove-lock local signing when CARTHA_EVM_PK is not set."""
    try:
        from eth_account import Account
    except ImportError:
        pytest.skip("eth_account not available")

    captured = {}

    # Generate a test private key
    test_account = Account.create()
    test_private_key = test_account.key.hex()
    test_address = test_account.address

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    # Ensure env var is not set
    monkeypatch.delenv("CARTHA_EVM_PK", raising=False)
    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)

    # Mock prompts
    prompt_responses = iter(
        [
            False,  # "Do you already have an EIP-712 signature? (y/n)" -> n
            True,  # "Sign locally with private key? (y/n)" -> y
            test_private_key,  # "EVM private key (0x...)" -> paste key
            True,  # "Is this your correct EVM address?" -> y
            True,  # "Submit this lock proof to the verifier?" -> y
        ]
    )

    def fake_confirm(*args, **kwargs):
        return next(prompt_responses, kwargs.get("default", True))

    def fake_prompt(*args, **kwargs):
        if "private key" in str(args[0]).lower():
            return next(prompt_responses)
        # Mock prompt for lock_days
        if "Lock period" in str(args[0]):
            return "30"  # Return default lock_days
        return "default"

    monkeypatch.setattr("typer.confirm", fake_confirm)
    monkeypatch.setattr("typer.prompt", fake_prompt)
    monkeypatch.setattr("rich.prompt.Confirm.ask", fake_confirm)

    result = runner.invoke(
        app,
        [
            "prove-lock",
            "--chain",
            "8453",
            "--vault",
            "0x000000000000000000000000000000000000dEaD",
            "--tx",
            "0x" + "ab" * 32,
            "--amount",
            "250",
            "--hotkey",
            "bt1xyz",
            "--slot",
            "9",
            "--pwd",
            "0x" + "44" * 32,
        ],
    )

    assert result.exit_code == 0
    assert "Lock proof submitted successfully." in result.stdout

    payload = captured["payload"]
    assert payload["minerEvmAddress"].lower() == test_address.lower()
    assert "signature" in payload
    assert payload["signature"].startswith("0x")


def test_prove_lock_signature_evm_address_mismatch(monkeypatch):
    """Test prove-lock when provided EVM address doesn't match private key."""
    try:
        from eth_account import Account
    except ImportError:
        pytest.skip("eth_account not available")

    captured = {}

    # Generate a test private key
    test_account = Account.create()
    test_private_key = test_account.key.hex()

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setenv("CARTHA_EVM_PK", test_private_key)
    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)

    # Mock prompts: user provides different EVM address
    prompt_responses = iter(
        [
            False,  # "Do you already have an EIP-712 signature? (y/n)" -> n
            True,  # "Sign locally with private key? (y/n)" -> y
            False,  # "Continue anyway?" -> n (reject mismatch)
        ]
    )

    def fake_confirm(*args, **kwargs):
        return next(prompt_responses)

    monkeypatch.setattr("typer.confirm", fake_confirm)

    result = runner.invoke(
        app,
        [
            "prove-lock",
            "--chain",
            "8453",
            "--vault",
            "0x000000000000000000000000000000000000dEaD",
            "--tx",
            "0x" + "ab" * 32,
            "--amount",
            "250",
            "--hotkey",
            "bt1xyz",
            "--slot",
            "9",
            "--miner-evm",
            "0x2222222222222222222222222222222222222222",  # Different address
            "--pwd",
            "0x" + "44" * 32,
        ],
    )

    # Should exit because user rejected the mismatch
    assert result.exit_code == 1


def test_prove_lock_external_signing_flow(monkeypatch):
    """Test prove-lock when user chooses external signing."""
    captured = {}

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)

    # Mock prompts: user chooses external signing
    prompt_responses = iter(
        [
            False,  # "Do you already have an EIP-712 signature? (y/n)" -> n
            False,  # "Sign locally with private key? (y/n)" -> n (external)
            "0x1111111111111111111111111111111111111111",  # EVM address (needed for EIP-712 message)
            "0x" + "77" * 65,  # Paste signature after external signing
            True,  # "Submit this lock proof to the verifier?" -> y
        ]
    )

    def fake_confirm(*args, **kwargs):
        return next(prompt_responses, kwargs.get("default", True))

    def fake_prompt(*args, **kwargs):
        # Mock prompt for lock_days
        if "Lock period" in str(args[0]):
            return "30"  # Return default lock_days
        return next(prompt_responses)

    monkeypatch.setattr("typer.confirm", fake_confirm)
    monkeypatch.setattr("typer.prompt", fake_prompt)
    monkeypatch.setattr("rich.prompt.Confirm.ask", fake_confirm)
    # Mock input() for "Press Enter when you have your signature ready"
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: "")

    result = runner.invoke(
        app,
        [
            "prove-lock",
            "--chain",
            "8453",
            "--vault",
            "0x000000000000000000000000000000000000dEaD",
            "--tx",
            "0x" + "ab" * 32,
            "--amount",
            "250",
            "--hotkey",
            "bt1xyz",
            "--slot",
            "9",
            "--pwd",
            "0x" + "44" * 32,
        ],
    )

    assert result.exit_code == 0
    # Should show message structure for external signing
    assert (
        "EIP-712 message files generated" in result.stdout
        or "Lock proof submitted successfully." in result.stdout
    )

    payload = captured["payload"]
    assert payload["signature"] == "0x" + "77" * 65


def test_generate_eip712_signature_helper(monkeypatch):
    """Test the _generate_eip712_signature helper function directly."""
    from eth_account import Account

    from cartha_cli.main import _generate_eip712_signature

    # Generate test account
    test_account = Account.create()
    test_private_key = test_account.key.hex()
    test_address = test_account.address

    # Test signature generation
    signature, derived_address = _generate_eip712_signature(
        chain_id=8453,
        vault_address="0x000000000000000000000000000000000000dEaD",
        miner_hotkey="bt1test",
        slot_uid="123",
        tx_hash="0x" + "ab" * 32,
        amount=250000000,
        password="0x" + "44" * 32,
        timestamp=1234567890,
        lock_days=30,
        private_key=test_private_key,
    )

    assert signature.startswith("0x")
    assert len(signature) == 132  # 0x + 130 hex chars
    assert derived_address.lower() == test_address.lower()


def test_prove_lock_payload_file_with_signature(monkeypatch):
    """Test prove-lock with payload file that includes signature (backward compatibility)."""
    import json
    import tempfile

    captured = {}

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)

    # Mock confirmation prompt
    def fake_confirm(*args, **kwargs):
        return kwargs.get("default", True)

    monkeypatch.setattr("rich.prompt.Confirm.ask", fake_confirm)

    # Create a temporary payload file
    payload_data = {
        "chain": 8453,
        "vault": "0x000000000000000000000000000000000000dEaD",
        "tx": "0x" + "ab" * 32,
        "amount": 250000000,
        "amountNormalized": "250",
        "hotkey": "5H1GvKsWc2dJJbfmfRTk58anZXKgPfDA8umj9d95CiYia9cH",  # Valid SS58 address
        "slot": "9",
        "miner_evm": "0x1111111111111111111111111111111111111111",
        "password": "0x" + "44" * 32,
        "signature": "0x" + "88" * 65,
        "timestamp": 1234567890,
        "lock_days": 30,  # Include lock_days
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(payload_data, f)
        payload_file = f.name

    try:
        result = runner.invoke(
            app,
            [
                "prove-lock",
                "--payload-file",
                payload_file,
            ],
        )

        assert result.exit_code == 0
        assert "Lock proof submitted successfully." in result.stdout

        payload = captured["payload"]
        assert (
            payload["minerHotkey"] == "5H1GvKsWc2dJJbfmfRTk58anZXKgPfDA8umj9d95CiYia9cH"
        )
        assert payload["slotUID"] == "9"
        assert payload["amount"] == 250000000
        assert payload["signature"] == "0x" + "88" * 65
        assert payload["lockDays"] == 30
    finally:
        import os

        os.unlink(payload_file)


def test_prove_lock_with_lock_days_cli(monkeypatch):
    """Test prove-lock with lock_days provided via CLI."""
    captured = {}

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    def fake_confirm(*args, **kwargs):
        return kwargs.get("default", True)

    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)
    monkeypatch.setattr("rich.prompt.Confirm.ask", fake_confirm)

    result = runner.invoke(
        app,
        [
            "prove-lock",
            "--chain",
            "8453",
            "--vault",
            "0x000000000000000000000000000000000000dEaD",
            "--tx",
            "0x" + "ab" * 32,
            "--amount",
            "250",
            "--hotkey",
            "bt1xyz",
            "--slot",
            "9",
            "--miner-evm",
            "0x1111111111111111111111111111111111111111",
            "--pwd",
            "0x" + "44" * 32,
            "--signature",
            "0x" + "55" * 65,
            "--lock-days",
            "90",
        ],
    )

    assert result.exit_code == 0
    payload = captured["payload"]
    assert payload["lockDays"] == 90


def test_prove_lock_lock_days_validation(monkeypatch):
    """Test that lock_days validation rejects values outside 7-365 range."""
    prompt_responses = iter(
        [
            "5",  # Too low - should reject
            "400",  # Too high - should reject
            "30",  # Valid
            True,  # Submit confirmation
        ]
    )

    def fake_prompt(*args, **kwargs):
        if "Lock period" in str(args[0]):
            return next(prompt_responses)
        return "default"

    def fake_confirm(*args, **kwargs):
        return next(prompt_responses, kwargs.get("default", True))

    monkeypatch.setattr("typer.prompt", fake_prompt)
    monkeypatch.setattr("rich.prompt.Confirm.ask", fake_confirm)

    # Mock submit to capture payload
    captured = {}

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)

    result = runner.invoke(
        app,
        [
            "prove-lock",
            "--chain",
            "8453",
            "--vault",
            "0x000000000000000000000000000000000000dEaD",
            "--tx",
            "0x" + "ab" * 32,
            "--amount",
            "250",
            "--hotkey",
            "bt1xyz",
            "--slot",
            "9",
            "--miner-evm",
            "0x1111111111111111111111111111111111111111",
            "--pwd",
            "0x" + "44" * 32,
            "--signature",
            "0x" + "55" * 65,
        ],
    )

    # Should eventually succeed with valid lock_days
    assert result.exit_code == 0
    payload = captured["payload"]
    assert payload["lockDays"] == 30


def test_prove_lock_payload_file_with_lock_days(monkeypatch):
    """Test prove-lock with payload file that includes lock_days."""
    import json
    import tempfile

    captured = {}

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)

    def fake_confirm(*args, **kwargs):
        return kwargs.get("default", True)

    monkeypatch.setattr("rich.prompt.Confirm.ask", fake_confirm)

    # Create a temporary payload file with lock_days
    payload_data = {
        "chain": 8453,
        "vault": "0x000000000000000000000000000000000000dEaD",
        "tx": "0x" + "ab" * 32,
        "amount": 250000000,
        "amountNormalized": "250",
        "hotkey": "5H1GvKsWc2dJJbfmfRTk58anZXKgPfDA8umj9d95CiYia9cH",
        "slot": "9",
        "miner_evm": "0x1111111111111111111111111111111111111111",
        "password": "0x" + "44" * 32,
        "signature": "0x" + "88" * 65,
        "timestamp": 1234567890,
        "lock_days": 180,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(payload_data, f)
        payload_file = f.name

    try:
        result = runner.invoke(
            app,
            [
                "prove-lock",
                "--payload-file",
                payload_file,
            ],
        )

        assert result.exit_code == 0
        payload = captured["payload"]
        assert payload["lockDays"] == 180
    finally:
        import os

        os.unlink(payload_file)


def test_prove_lock_payload_file_missing_lock_days(monkeypatch):
    """Test that missing lock_days in payload file causes error."""
    import json
    import tempfile

    # Create a temporary payload file without lock_days
    payload_data = {
        "chain": 8453,
        "vault": "0x000000000000000000000000000000000000dEaD",
        "tx": "0x" + "ab" * 32,
        "amount": 250000000,
        "amountNormalized": "250",
        "hotkey": "5H1GvKsWc2dJJbfmfRTk58anZXKgPfDA8umj9d95CiYia9cH",
        "slot": "9",
        "miner_evm": "0x1111111111111111111111111111111111111111",
        "password": "0x" + "44" * 32,
        "signature": "0x" + "88" * 65,
        "timestamp": 1234567890,
        # Missing lock_days
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(payload_data, f)
        payload_file = f.name

    try:
        result = runner.invoke(
            app,
            [
                "prove-lock",
                "--payload-file",
                payload_file,
            ],
        )

        assert result.exit_code == 1
        assert (
            "lock_days" in result.stdout.lower()
            or "missing required fields" in result.stdout.lower()
        )
    finally:
        import os

        os.unlink(payload_file)


def test_prove_lock_lock_days_in_eip712_signature(monkeypatch):
    """Test that lock_days is included in EIP-712 signature generation."""
    try:
        from eth_account import Account
    except ImportError:
        pytest.skip("eth_account not available")

    captured = {}

    test_account = Account.create()
    test_private_key = test_account.key.hex()

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setenv("CARTHA_EVM_PK", test_private_key)
    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)

    prompt_responses = iter(
        [
            False,  # No signature
            True,  # Sign locally
            True,  # Confirm EVM address
            True,  # Submit
        ]
    )

    def fake_confirm(*args, **kwargs):
        return next(prompt_responses, kwargs.get("default", True))

    monkeypatch.setattr("typer.confirm", fake_confirm)
    monkeypatch.setattr("rich.prompt.Confirm.ask", fake_confirm)

    # Mock prompt for lock_days
    def fake_prompt(*args, **kwargs):
        if "Lock period" in str(args[0]):
            return "60"  # Return 60 days
        return "default"

    monkeypatch.setattr("typer.prompt", fake_prompt)

    result = runner.invoke(
        app,
        [
            "prove-lock",
            "--chain",
            "8453",
            "--vault",
            "0x000000000000000000000000000000000000dEaD",
            "--tx",
            "0x" + "ab" * 32,
            "--amount",
            "250",
            "--hotkey",
            "bt1xyz",
            "--slot",
            "9",
            "--pwd",
            "0x" + "44" * 32,
        ],
    )

    assert result.exit_code == 0
    payload = captured["payload"]
    assert payload["lockDays"] == 60
    assert "signature" in payload
