"""Generic high-entropy detector — the deliberately-demoted ``POSSIBLE`` path.

Entropy is the false-positive-prone path, so anything it emits is structurally
``Confidence.POSSIBLE`` and never blocks a commit by default. Git SHAs, SHA-256
hashes and UUIDs are pre-excluded here (cheap, structural) so they never even
become findings — the structural suppressor is a second line of defence.
"""

from __future__ import annotations

import math
import re

from ..models import Confidence, Detector, Severity

# Tokenizer: split each line on anything that is not a plausible secret char.
_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9+/=_\-]+")

_HEX_ONLY = re.compile(r"\A[0-9a-fA-F]+\Z")
_BASE64ISH = re.compile(r"\A[A-Za-z0-9+/=]+\Z")

# Structural shapes to drop before emitting (defence in depth with the suppressor).
_GIT_SHA = re.compile(r"\A[0-9a-f]{40}\Z")  # SHA-1 (lower hex)
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")  # SHA-256 (lower hex)
_UUID = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)

DEFAULT_B64_THRESHOLD = 4.5
DEFAULT_HEX_THRESHOLD = 3.0
MIN_B64_LEN = 20
MIN_HEX_LEN = 32


def shannon_entropy(s: str) -> float:
    """Shannon entropy H = -Σ p(c)·log2 p(c) over the characters of ``s`` (bits/char)."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_structural(token: str) -> bool:
    return bool(_GIT_SHA.match(token) or _SHA256.match(token) or _UUID.match(token))


def _qualifies(token: str, b64_threshold: float, hex_threshold: float) -> bool:
    if _is_structural(token):
        return False
    h = shannon_entropy(token)
    if _HEX_ONLY.match(token):
        return len(token) >= MIN_HEX_LEN and h >= hex_threshold
    if _BASE64ISH.match(token):
        return len(token) >= MIN_B64_LEN and h >= b64_threshold
    # generic charset (contains - or _): treat like base64 thresholds.
    return len(token) >= MIN_B64_LEN and h >= b64_threshold


def make_entropy_detector(
    b64_threshold: float = DEFAULT_B64_THRESHOLD,
    hex_threshold: float = DEFAULT_HEX_THRESHOLD,
) -> Detector:
    """Build the generic entropy detector with tunable thresholds."""

    def find(line: str) -> list[tuple[str, int, int]]:
        out: list[tuple[str, int, int]] = []
        pos = 0
        for token in _TOKEN_SPLIT.split(line):
            if not token:
                pos = line.find("", pos)
                continue
            start = line.find(token, pos)
            if start < 0:
                continue
            end = start + len(token)
            pos = end
            if len(token) < MIN_B64_LEN:
                continue
            if _qualifies(token, b64_threshold, hex_threshold):
                out.append((token, start, end))
        return out

    return Detector(
        id="high-entropy-string",
        name="High-entropy string",
        confidence=Confidence.POSSIBLE,
        severity=Severity.MEDIUM,
        pattern=None,
        find=find,
    )
