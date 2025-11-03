import json
import sys
import types
from pathlib import Path

from typer.testing import CliRunner

sys.path.append(str(Path(__file__).resolve().parents[1]))


class _StubKeyFileError(Exception):
    pass


class _StubKeypair:
    def __init__(self, ss58_address: str | None = None):
        self.ss58_address = ss58_address

    def verify(self, message: bytes, signature: bytes) -> bool:  # pragma: no cover - stub
        return True


class _StubWeb3:
    @staticmethod
    def is_address(value: str) -> bool:
        return True

    @staticmethod
    def to_checksum_address(value: str) -> str:
        return value


bt_stub = types.SimpleNamespace(
    KeyFileError=_StubKeyFileError,
    Keypair=_StubKeypair,
    wallet=lambda *args, **kwargs: None,
    subtensor=lambda *args, **kwargs: None,
)
sys.modules.setdefault("bittensor", bt_stub)
sys.modules.setdefault("web3", types.SimpleNamespace(Web3=_StubWeb3))

from cartha_cli.bt import RegistrationResult
from cartha_cli.main import app
from cartha_cli import main as cli_main


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

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)
    monkeypatch.setattr("cartha_cli.main._build_pair_auth_payload", fake_auth_payload)
    monkeypatch.setattr("cartha_cli.main.register_pair_password", fake_issue)

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
    assert "Registration success" in result.stdout
    assert "Registered UID: 10" in result.stdout
    assert "Pair password for bt1abc/10" in result.stdout


def test_register_command_already(monkeypatch):
    def fake_register_hotkey(**kwargs):
        return RegistrationResult(status="already", success=True, uid=7, hotkey="bt1abc")

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)

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
        return RegistrationResult(status="pow", success=False, uid=None, hotkey="bt1abc")

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)
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
    def fake_register_hotkey(**kwargs):
        raise cli_main.bt.KeyFileError("missing keyfile")

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)

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
    assert "Unable to open coldkey 'cold' hotkey 'bt1abc'" in result.stdout


def test_register_command_trace_unexpected(monkeypatch):
    def fake_register_hotkey(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)

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
    assert "Registration failed unexpectedly" in result.stdout

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

    monkeypatch.setattr("cartha_cli.main._build_pair_auth_payload", fake_auth_payload)
    monkeypatch.setattr("cartha_cli.main._request_pair_status_or_password", fake_request)
    monkeypatch.setattr(
        "cartha_cli.main._load_wallet",
        lambda wallet_name, wallet_hotkey, expected: DummyWallet("bt1xyz"),
    )
    monkeypatch.setattr(
        "cartha_cli.main._ensure_pair_registered", lambda **kwargs: None
    )

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
    assert "0x22" not in result.stdout


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

    monkeypatch.setattr("cartha_cli.main._build_pair_auth_payload", fake_auth_payload)
    monkeypatch.setattr("cartha_cli.main._request_pair_status_or_password", fake_request)
    monkeypatch.setattr(
        "cartha_cli.main._load_wallet",
        lambda wallet_name, wallet_hotkey, expected: DummyWallet("bt1xyz"),
    )
    monkeypatch.setattr(
        "cartha_cli.main._ensure_pair_registered", lambda **kwargs: None
    )

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
    payload = json.loads(stdout[json_start:])
    assert payload["state"] == "pending"
    assert payload["hotkey"] == "bt1xyz"
    assert payload["slot"] == "7"
    assert "pwd" not in payload


def test_prove_lock_command_success(monkeypatch):
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
    assert payload["amount"] == 12345
    assert payload["pwd"] == "0x" + "44" * 32
