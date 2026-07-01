"""Detector unit tests — true-positive recall + entropy math (plan tests 11-20)."""

from __future__ import annotations

from envsentry.detectors import make_entropy_detector, shannon_entropy
from envsentry.detectors.providers import PROVIDERS

BY_ID = {d.id: d for d in PROVIDERS}


def _hits(detector_id: str, line: str) -> list[str]:
    det = BY_ID[detector_id]
    return [tok for tok, _s, _e in det.find(line)]


# --- true positives (11-17) -------------------------------------------------
def test_tp_aws_akia():
    assert _hits("aws-access-key-id", 'key = "AKIAIOSFODNN7EXAMPLE"') == ["AKIAIOSFODNN7EXAMPLE"]


def test_tp_aws_akia_negative():
    # lowercase / too-short must NOT match.
    assert _hits("aws-access-key-id", "akiaiosfodnn7example") == []
    assert _hits("aws-access-key-id", "AKIA123") == []


def test_tp_github_pat():
    tok = "ghp_A1b2C3d4E5f6G7h8J9k0L1m2N3o4P5q6R7s8"
    assert _hits("github-pat", f'token = "{tok}"') == [tok]
    assert _hits("github-pat", "token = ghp_tooShort") == []


def test_tp_slack_bot():
    tok = "xoxb-A1b2C3d4E5-F6g7H8j9K0-LmNoPqRsTuVw"
    assert _hits("slack-bot-token", f'slack = "{tok}"') == [tok]


def test_tp_stripe_live_and_test_are_separate():
    live = "sk_live_" + "A1b2C3d4E5f6G7h8J9k0L1m2"
    test = "sk_test_" + "A1b2C3d4E5f6G7h8J9k0L1m2"
    assert _hits("stripe-secret-live", live) == [live]
    assert _hits("stripe-secret-live", test) == []
    assert _hits("stripe-secret-test", test) == [test]
    assert BY_ID["stripe-secret-live"].severity.value == "high"
    assert BY_ID["stripe-secret-test"].severity.value == "medium"


def test_tp_google_api():
    tok = "AIzaSy1aBcD2eFgH3iJkL4mNoP5qRsT6uVwX7yZ"
    assert _hits("google-api-key", f'k = "{tok}"') == [tok]


def test_tp_jwt_valid_header_only():
    good = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhYmMiLCJuYW1lIjoiSm9obiBEb2UifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    assert _hits("jwt", good) == [good]
    # eyJ... whose header does NOT base64/JSON-decode to an object with "alg".
    bad = "eyJnotbase64json.aaaaaaaaaaaa.bbbbbbbbbbbb"
    assert _hits("jwt", bad) == []


def test_tp_private_key_block_not_certificate():
    assert _hits("private-key-block", "-----BEGIN OPENSSH PRIVATE KEY-----")
    assert _hits("private-key-block", "-----BEGIN RSA PRIVATE KEY-----")
    assert _hits("private-key-block", "-----BEGIN CERTIFICATE-----") == []


def test_aws_secret_needs_keyword_and_entropy():
    tok = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40 chars
    assert _hits("aws-secret-access-key", f'aws_secret_access_key = "{tok}"') == [tok]
    # Same token with no aws/secret keyword nearby -> not flagged (FP guard).
    assert _hits("aws-secret-access-key", f'value = "{tok}"') == []


# --- entropy detector (18-20) ----------------------------------------------
def test_tp_generic_entropy_possible():
    det = make_entropy_detector()
    tok = "Kj8xQvN2pLm5RtY7wZ3bC6dF9gH1aS4e"  # random-ish 32-char base64
    hits = det.find(f'secret = "{tok}"')
    assert [t for t, _s, _e in hits] == [tok]
    assert det.confidence.value == "possible"


def test_fp_english_prose_not_flagged():
    det = make_entropy_detector()
    prose = "the quick brown fox jumps over the lazy dog several times in a row"
    assert det.find(prose) == []


def test_entropy_pre_excludes_sha_and_uuid():
    det = make_entropy_detector()
    assert det.find("9c8b7a6d5e4f3c2b1a0f9e8d7c6b5a4d3e2f1a0b") == []  # git SHA-1
    assert det.find("550e8400-e29b-41d4-a716-446655440000") == []  # UUID


def test_entropy_shannon_value():
    assert round(shannon_entropy("aabb"), 3) == 1.0
    assert round(shannon_entropy("abcd"), 3) == 2.0
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_boundary():
    det = make_entropy_detector(b64_threshold=4.5)
    low = "ABCDEFGHIJKLMNOPQRSTUV"  # 22 unique -> H = log2(22) = 4.459 (< 4.5)
    high = "ABCDEFGHIJKLMNOPQRSTUVW"  # 23 unique -> H = log2(23) = 4.524 (> 4.5)
    assert round(shannon_entropy(low), 2) == 4.46
    assert round(shannon_entropy(high), 2) == 4.52
    assert det.find(f"x = {low}") == []
    assert [t for t, _s, _e in det.find(f"x = {high}")] == [high]
