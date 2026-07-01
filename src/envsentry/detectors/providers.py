"""Provider-format detectors — all ``Confidence.VERIFIED``.

Each detector is a data-driven ``Detector`` entry with a boundary-anchored regex
and, where useful, a secondary ``validate`` (JWT header decode, AWS entropy +
keyword proximity). Every provider ships a paired positive + negative unit test.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable

from ..models import Confidence, Detector, Severity
from .entropy import shannon_entropy


def _regex_find(
    pattern: re.Pattern,
    validate: Callable[[str], bool] | None = None,
) -> Callable[[str], list[tuple[str, int, int]]]:
    def find(line: str) -> list[tuple[str, int, int]]:
        out: list[tuple[str, int, int]] = []
        for m in pattern.finditer(line):
            tok = m.group(0)
            if validate is not None and not validate(tok):
                continue
            out.append((tok, m.start(), m.end()))
        return out

    return find


# --- JWT validator ---------------------------------------------------------
def _jwt_valid(token: str) -> bool:
    """A real JWT's first segment base64url-decodes to a JSON object with an ``alg``."""
    header_b64 = token.split(".", 1)[0]
    pad = "=" * (-len(header_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(header_b64 + pad)
        obj = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    return isinstance(obj, dict) and "alg" in obj


# --- AWS secret access key (context + entropy gated) -----------------------
_AWS_SECRET_RX = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
_AWS_KEYWORD = re.compile(r"aws|secret|access[_-]?key", re.IGNORECASE)


def _aws_secret_find(line: str) -> list[tuple[str, int, int]]:
    # Only consider 40-char tokens that sit near an aws/secret keyword: this is
    # the single biggest FP-cutter for the unavoidably-broad 40-char shape.
    if not _AWS_KEYWORD.search(line):
        return []
    out: list[tuple[str, int, int]] = []
    for m in _AWS_SECRET_RX.finditer(line):
        tok = m.group(0)
        if shannon_entropy(tok) > 4.0:
            out.append((tok, m.start(), m.end()))
    return out


def _make(
    id: str,
    name: str,
    severity: Severity,
    pattern: re.Pattern,
    validate: Callable[[str], bool] | None = None,
) -> Detector:
    return Detector(
        id=id,
        name=name,
        confidence=Confidence.VERIFIED,
        severity=severity,
        pattern=pattern,
        find=_regex_find(pattern, validate),
        validate=validate,
    )


# --- compiled provider patterns -------------------------------------------
_AWS_ACCESS = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")
_GITHUB_PAT = re.compile(r"(?<![A-Za-z0-9])gh[posru]_[A-Za-z0-9]{36}(?![A-Za-z0-9])")
_GITHUB_FG = re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{82}(?![A-Za-z0-9])")
_SLACK_BOT = re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[0-9A-Za-z-]{10,48}(?![A-Za-z0-9])")
_STRIPE_LIVE = re.compile(r"(?<![A-Za-z0-9])sk_live_[0-9A-Za-z]{24,}(?![A-Za-z0-9])")
_STRIPE_TEST = re.compile(r"(?<![A-Za-z0-9])sk_test_[0-9A-Za-z]{24,}(?![A-Za-z0-9])")
_GOOGLE_API = re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9\-_])")
_GOOGLE_OAUTH = re.compile(r"\b[0-9]{12}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP|PRIVATE) ?(?:PRIVATE )?KEY-----")
_SLACK_HOOK = re.compile(
    r"https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+"
)


PROVIDERS: list[Detector] = [
    _make("aws-access-key-id", "AWS Access Key ID", Severity.HIGH, _AWS_ACCESS),
    Detector(
        id="aws-secret-access-key",
        name="AWS Secret Access Key",
        confidence=Confidence.VERIFIED,
        severity=Severity.HIGH,
        pattern=_AWS_SECRET_RX,
        find=_aws_secret_find,
        validate=lambda t: shannon_entropy(t) > 4.0,
    ),
    _make("github-pat", "GitHub Personal Access Token", Severity.HIGH, _GITHUB_PAT),
    _make("github-fine-grained-pat", "GitHub Fine-Grained PAT", Severity.HIGH, _GITHUB_FG),
    _make("slack-bot-token", "Slack Bot/User Token", Severity.HIGH, _SLACK_BOT),
    _make("stripe-secret-live", "Stripe Live Secret Key", Severity.HIGH, _STRIPE_LIVE),
    _make("stripe-secret-test", "Stripe Test Secret Key", Severity.MEDIUM, _STRIPE_TEST),
    _make("google-api-key", "Google API Key", Severity.HIGH, _GOOGLE_API),
    _make("google-oauth-id", "Google OAuth Client ID", Severity.MEDIUM, _GOOGLE_OAUTH),
    _make("jwt", "JSON Web Token", Severity.MEDIUM, _JWT, validate=_jwt_valid),
    _make("private-key-block", "Private Key Block (PEM)", Severity.HIGH, _PRIVATE_KEY),
    _make("slack-webhook", "Slack Incoming Webhook", Severity.MEDIUM, _SLACK_HOOK),
]
