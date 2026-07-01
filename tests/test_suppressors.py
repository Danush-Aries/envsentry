"""False-positive suppression tests (plan tests 1-9). These are the product's proof."""

from __future__ import annotations

from envsentry.context.suppressors import PLACEHOLDER, STRUCTURAL, VARNAME_EXAMPLE
from envsentry.models import Confidence, Finding, Secret, Severity
from envsentry.scanner import ScanConfig, scan_text


def _finding(token: str, path: str = "src/app.py", line_text: str = "", detector: str = "x"):
    sec = Secret(detector, token, Confidence.VERIFIED, Severity.HIGH)
    return Finding(sec, path, 1, 1, line_text or token)


# --- 1-3 structural (direct suppressor) ------------------------------------
def test_fp_uuid_not_flagged():
    assert STRUCTURAL.applies(_finding("550e8400-e29b-41d4-a716-446655440000"))


def test_fp_git_sha_not_flagged():
    assert STRUCTURAL.applies(_finding("9c8b7a6d5e4f3c2b1a0f9e8d7c6b5a4d3e2f1a0b"))
    assert STRUCTURAL.applies(_finding("9c8b7a6"))
    # a mixed-case high-entropy secret is NOT structural.
    assert not STRUCTURAL.applies(_finding("Kj8xQvN2pLm5RtY7wZ3bC6dF"))


def test_fp_sha256_hash_not_flagged():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert STRUCTURAL.applies(_finding(h))


# --- 4 path-allowlist -------------------------------------------------------
def test_fp_env_example_file():
    line = 'API_KEY = "AIzaSy1aBcD2eFgH3iJkL4mNoP5qRsT6uVwX7yZ"'
    report = scan_text(".env.example", line)
    assert report.verified == []
    assert report.suppressed and report.suppressed[0].suppressed_by == "path-allowlist"


def test_fp_same_key_in_src_is_active():
    line = 'API_KEY = "AIzaSy1aBcD2eFgH3iJkL4mNoP5qRsT6uVwX7yZ"'
    report = scan_text("src/config.py", line)
    assert len(report.verified) == 1


# --- 5 varname-example ------------------------------------------------------
def test_fp_example_varname():
    example = 'EXAMPLE_API_KEY = "AKIAIOSFODNN7EXAMPLE"'
    prod = 'PROD_API_KEY = "AKIAIOSFODNN7EXAMPLE"'
    assert VARNAME_EXAMPLE.applies(_finding("AKIAIOSFODNN7EXAMPLE", line_text=example))
    assert not VARNAME_EXAMPLE.applies(_finding("AKIAIOSFODNN7EXAMPLE", line_text=prod))
    assert scan_text("src/config.py", example).verified == []
    assert len(scan_text("src/config.py", prod).verified) == 1


# --- 6 placeholder ----------------------------------------------------------
def test_fp_placeholder_tokens():
    assert PLACEHOLDER.applies(_finding("AKIA0000000000000000"))
    assert PLACEHOLDER.applies(_finding("sk_live_" + "x" * 24))
    assert PLACEHOLDER.applies(_finding("token", line_text="key = <your-api-key-here>"))
    # a real-looking token is NOT a placeholder.
    assert not PLACEHOLDER.applies(_finding("AKIAIOSFODNN7EXAMPLE"))
    # end to end: both real-format placeholders suppressed, 0 blocking.
    blob = 'A = "AKIA0000000000000000"\nB = "sk_live_' + "x" * 24 + '"'
    assert scan_text("src/config.py", blob).verified == []


# --- 7 prose ---------------------------------------------------------------
def test_fp_english_prose_high_len():
    prose = "the expected environment variables are documented here for local development use"
    assert scan_text("src/config.py", prose).active == []


# --- 8 test-fixture path (suppressed but visible) --------------------------
def test_fp_test_fixture_path():
    line = 'aws = "AKIAIOSFODNN7EXAMPLE"'
    report = scan_text("tests/fixtures/keys.txt", line)
    assert report.verified == []  # not blocking
    assert any(f.suppressed_by == "path-allowlist" for f in report.suppressed)  # still visible


# --- 9 lockfile integrity hash ---------------------------------------------
def test_fp_lockfile_integrity_hash():
    line = '"integrity": "sha512-Q9d0aB3xY7pL2mN8vC4wZ1kR6tE5uI0oP3sD7fG9hJ2lK4nM6bV8cX1zA5yW7qT"'
    report = scan_text("package-lock.json", line, ScanConfig())
    assert report.verified == []  # only POSSIBLE at most, never blocking
