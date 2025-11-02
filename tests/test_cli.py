from pathlib import Path
import sys

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
        return RegistrationResult(status="pow", success=True, uid=10)

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)
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


def test_register_command_already(monkeypatch):
    def fake_register_hotkey(**kwargs):
        return RegistrationResult(status="already", success=True, uid=7)

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)
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
        return RegistrationResult(status="pow", success=False, uid=None)

    monkeypatch.setattr("cartha_cli.main.register_hotkey", fake_register_hotkey)
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
