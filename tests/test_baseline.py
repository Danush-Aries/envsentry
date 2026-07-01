"""Baseline / hashed-allowlist tests (plan tests 21-23)."""

from __future__ import annotations

from pathlib import Path

from envsentry.context import accept, fingerprint
from envsentry.scanner import ScanConfig, scan_text

_LINE = 'aws = "AKIAIOSFODNN7EXAMPLE"'


def test_baseline_suppresses(tmp_path: Path):
    baseline = tmp_path / ".envsentry-allow"
    first = scan_text("src/config.py", _LINE)
    assert len(first.verified) == 1
    accept(first.verified, baseline)

    cfg = ScanConfig(baseline_path=str(baseline))
    second = scan_text("src/config.py", _LINE, cfg)
    assert second.verified == []
    assert second.suppressed[0].suppressed_by == "baseline"


def test_baseline_rotation_resurfaces(tmp_path: Path):
    baseline = tmp_path / ".envsentry-allow"
    accept(scan_text("src/config.py", _LINE).verified, baseline)

    rotated = 'aws = "AKIAZ9Y8X7W6V5U4T3S2"'  # different token -> different fingerprint
    cfg = ScanConfig(baseline_path=str(baseline))
    report = scan_text("src/config.py", rotated, cfg)
    assert len(report.verified) == 1  # re-surfaces after rotation


def test_baseline_writes_no_secret(tmp_path: Path):
    baseline = tmp_path / ".envsentry-allow"
    report = scan_text("src/config.py", _LINE)
    accept(report.verified, baseline)
    contents = baseline.read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in contents
    # only the fingerprint is present.
    assert fingerprint(report.verified[0]) in contents


def test_fingerprint_is_stable_and_token_bound():
    a = scan_text("src/config.py", _LINE).verified[0]
    b = scan_text("src/config.py", _LINE).verified[0]
    assert fingerprint(a) == fingerprint(b)
    c = scan_text("other/config.py", _LINE).verified[0]
    assert fingerprint(a) != fingerprint(c)  # path-bound
