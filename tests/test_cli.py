"""CLI integration tests: exit codes + JSON format (plan tests 26-27)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from envsentry.cli import app

runner = CliRunner()


def test_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0
    assert "envsentry" in r.stdout


def test_exit_code_clean_is_zero(tmp_path: Path):
    f = tmp_path / "clean.py"
    f.write_text('greeting = "hello world"\ncount = 42\n')
    r = runner.invoke(app, ["audit", str(f)])
    assert r.exit_code == 0
    assert "Clean" in r.stdout


def test_exit_code_verified_is_one(tmp_path: Path):
    f = tmp_path / "leak.py"
    f.write_text('aws = "AKIAIOSFODNN7EXAMPLE"\n')
    r = runner.invoke(app, ["audit", str(f)])
    assert r.exit_code == 1
    assert "VERIFIED" in r.stdout


def test_exit_code_error_is_two():
    r = runner.invoke(app, ["audit", "/no/such/path/really"])
    assert r.exit_code == 2


def test_possible_does_not_block_by_default(tmp_path: Path):
    f = tmp_path / "entropy.py"
    f.write_text('blob = "Kj8xQvN2pLm5RtY7wZ3bC6dF9gH1aS4e"\n')
    r = runner.invoke(app, ["audit", str(f)])
    assert r.exit_code == 0  # POSSIBLE never blocks with default --fail-on verified
    r2 = runner.invoke(app, ["audit", str(f), "--fail-on", "possible"])
    assert r2.exit_code == 1  # opt-in blocking


def test_scan_json_format_redacts(tmp_path: Path):
    f = tmp_path / "leak.py"
    f.write_text('aws = "AKIAIOSFODNN7EXAMPLE"\n')
    r = runner.invoke(app, ["audit", str(f), "--format", "json"])
    payload = json.loads(r.stdout)
    assert payload["tool"] == "envsentry"
    assert payload["summary"]["verified"] == 1
    finding = payload["findings"][0]
    assert finding["confidence"] == "verified"
    assert "AKIAIOSFODNN7EXAMPLE" not in r.stdout  # full token never leaked by default
    assert finding["redacted"].startswith("AKIA")
    assert "token" not in finding


def test_scan_json_show_reveals_token(tmp_path: Path):
    f = tmp_path / "leak.py"
    f.write_text('aws = "AKIAIOSFODNN7EXAMPLE"\n')
    r = runner.invoke(app, ["audit", str(f), "--format", "json", "--show"])
    payload = json.loads(r.stdout)
    assert payload["findings"][0]["token"] == "AKIAIOSFODNN7EXAMPLE"
