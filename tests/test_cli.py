import sys
import json
from pathlib import Path

from typer.testing import CliRunner

sys.path.append(str(Path(__file__).resolve().parents[1]))

from cartha_cli.main import app
from cartha_cli.bt import RegistrationResult


runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_register_command_success(monkeypatch):
    def fake_register_hotkey(**kwargs):
        return RegistrationResult(status="pow", success=True, uid=10, hotkey="bt1abc")

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)
    monkeypatch.setattr(
        "cartha_cli.main.fetch_pair_password",
        lambda hotkey, slot: {"pwd": "0x" + "11" * 32},
    )
    result = runner.invoke(
        app,
        [
            "s",
            "register",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "hot",
            "--network",
            "finney",
            "--netuid",
            "35",
        ],
    )
    assert result.exit_code == 0
    assert "Registration success." in result.stdout
    assert "Registered uid: 10" in result.stdout
    assert "Pair password for bt1abc/10: 0x11" in result.stdout


def test_register_command_already(monkeypatch):
    def fake_register_hotkey(**kwargs):
        return RegistrationResult(status="already", success=True, uid=7, hotkey="bt1abc")

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)
    monkeypatch.setattr("cartha_cli.main.fetch_pair_password", lambda *args, **kwargs: None)
    result = runner.invoke(
        app,
        [
            "s",
            "register",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "hot",
        ],
    )
    assert result.exit_code == 0
    assert "Hotkey already registered" in result.stdout
    assert "UID: 7" in result.stdout


def test_register_command_failure(monkeypatch):
    def fake_register_hotkey(**kwargs):
        return RegistrationResult(status="pow", success=False, uid=None, hotkey="bt1abc")

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)
    monkeypatch.setattr("cartha_cli.main.fetch_pair_password", lambda *args, **kwargs: None)
    result = runner.invoke(
        app,
        [
            "s",
            "register",
            "--wallet-name",
            "cold",
            "--wallet-hotkey",
            "hot",
        ],
    )
    assert result.exit_code == 1
    assert "Registration failed" in result.stdout


def test_pair_status_command_hides_password(monkeypatch):
    def fake_status(hotkey, slot):
        return {
            "state": "active",
            "has_pwd": True,
            "pwd": "0x" + "22" * 32,
            "issued_at": "2024-05-20T12:00:00Z",
        }

    monkeypatch.setattr("cartha_cli.main.fetch_pair_status", fake_status)
    result = runner.invoke(
        app,
        ["pair", "status", "--hotkey", "bt1xyz", "--slot", "42"],
    )
    assert result.exit_code == 0
    assert "State: active" in result.stdout
    assert "Password issued: yes" in result.stdout
    assert "0x22" not in result.stdout


def test_pair_status_command_json(monkeypatch):
    def fake_status(hotkey, slot):
        return {
            "state": "pending",
            "has_pwd": False,
            "pwd": "0x" + "33" * 32,
            "issued_at": None,
        }

    monkeypatch.setattr("cartha_cli.main.fetch_pair_status", fake_status)
    result = runner.invoke(
        app,
        ["pair", "status", "--hotkey", "bt1xyz", "--slot", "7", "--json"],
    )
    assert result.exit_code == 0
    stdout = result.stdout
    json_start = stdout.find("{")
    assert json_start != -1
    payload = json.loads(stdout[json_start:])
    assert payload["state"] == "pending"
    assert payload["hotkey"] == "bt1xyz"
    assert payload["slot"] == "7"
    assert "pwd" not in payload


class DummySignedMessage:
    def __init__(self, signature: bytes) -> None:
        self.signature = signature


class DummyAccount:
    def __init__(self, address: str) -> None:
        self.address = address

    def sign_message(self, _message):
        return DummySignedMessage(b"\xaa" * 65)


def test_prove_lock_command_success(monkeypatch):
    def fake_status(hotkey, slot):
        return {"state": "active", "has_pwd": True}

    def fake_password(hotkey, slot):
        return {"pwd": "0x" + "44" * 32}

    captured = {}

    def fake_submit(payload):
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr("cartha_cli.main.fetch_pair_status", fake_status)
    monkeypatch.setattr("cartha_cli.main.fetch_pair_password", fake_password)
    monkeypatch.setattr("cartha_cli.main.submit_lock_proof", fake_submit)
    monkeypatch.setattr(
        "cartha_cli.main._load_evm_account",
        lambda: DummyAccount("0x1111111111111111111111111111111111111111"),
    )

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
        ],
    )

    assert result.exit_code == 0
    assert "Lock proof submitted successfully." in result.stdout
    assert "payload" in captured
    payload = captured["payload"]
    assert payload["minerHotkey"] == "bt1xyz"
    assert payload["slotUID"] == "9"
    assert payload["amount"] == 12345
    assert payload["pwd"] == "0x" + "44" * 32
