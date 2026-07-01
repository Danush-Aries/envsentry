"""Shared data contract for envsentry.

Frozen before any other module is written. Every module — detectors, context,
git, report, scanner, cli — codes against these types. Standard-library only
(``dataclasses``, ``enum``, ``re``, ``typing``); no third-party type ever leaks
into the contract, so this stays the stable center of the package.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from re import Pattern


class Confidence(str, Enum):
    """How sure we are a token is a real secret.

    ``VERIFIED`` = matched a provider-specific format regex (offline, format-only —
    explicitly NOT verified-live like trufflehog). ``POSSIBLE`` = entropy-only,
    no known provider format. Commits fail by default only on ``VERIFIED``.
    """

    VERIFIED = "verified"
    POSSIBLE = "possible"


class Severity(str, Enum):
    HIGH = "high"  # live-cred-class providers (AWS, Stripe live, private key)
    MEDIUM = "medium"  # tokens, generic entropy
    LOW = "low"


@dataclass(frozen=True)
class Detector:
    """A single detection rule. Pure and deterministic; performs no I/O."""

    id: str  # "aws-access-key-id"
    name: str  # "AWS Access Key ID"
    confidence: Confidence  # VERIFIED for a provider regex, POSSIBLE for entropy
    severity: Severity
    pattern: Pattern | None  # compiled regex; None for the entropy detector
    # find(line) -> list of (matched_token, start_col, end_col) 0-based half-open.
    find: Callable[[str], list[tuple[str, int, int]]]
    # optional secondary validator (JWT header decode, entropy check, ...).
    validate: Callable[[str], bool] | None = None


@dataclass(frozen=True)
class Secret:
    """A raw candidate located in source, before context filtering."""

    detector_id: str
    token: str  # the matched substring (never logged in full by report)
    confidence: Confidence
    severity: Severity


@dataclass
class Finding:
    """A ``Secret`` placed in file/line context: post-detection, pre/post-suppression."""

    secret: Secret
    path: str  # file path or "<staged>"
    line: int  # 1-based line number
    col: int  # 1-based column of token start
    line_text: str  # full source line (redacted in default output)
    suppressed: bool = False
    suppressed_by: str | None = None  # suppressor id that killed it
    fingerprint: str = ""  # stable hash; computed by the baseline layer

    @property
    def confidence(self) -> Confidence:
        return self.secret.confidence

    @property
    def severity(self) -> Severity:
        return self.secret.severity

    @property
    def detector_id(self) -> str:
        return self.secret.detector_id

    @property
    def redacted(self) -> str:
        """token -> first4 + '…' + last2, or '****' when too short to redact safely."""
        t = self.secret.token
        if len(t) <= 8:
            return "****"
        return f"{t[:4]}…{t[-2:]}"


@dataclass(frozen=True)
class Suppressor:
    """A context rule that may mark a ``Finding`` as suppressed."""

    id: str  # "placeholder" | "varname-example" | "path-allowlist" | ...
    reason: str
    applies: Callable[[Finding], bool]  # True -> this finding should be suppressed


@dataclass
class Report:
    findings: list[Finding]  # ALL findings (suppressed + active)
    scanned_paths: list[str] = field(default_factory=list)

    @property
    def active(self) -> list[Finding]:
        """Findings that survived every suppressor and the baseline."""
        return [f for f in self.findings if not f.suppressed]

    @property
    def verified(self) -> list[Finding]:
        return [f for f in self.active if f.confidence is Confidence.VERIFIED]

    @property
    def possible(self) -> list[Finding]:
        return [f for f in self.active if f.confidence is Confidence.POSSIBLE]

    @property
    def suppressed(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    def exit_code(self, fail_on: Confidence = Confidence.VERIFIED) -> int:
        """0 = clean/all-suppressed · 1 = blocking findings exist per ``fail_on``.

        With ``fail_on=VERIFIED`` (default), only active VERIFIED findings block —
        entropy noise (POSSIBLE) can never stop a commit unless the developer opts
        in with ``fail_on=POSSIBLE``.
        """
        if fail_on is Confidence.VERIFIED:
            return 1 if self.verified else 0
        # POSSIBLE / "any": any active finding of either tier blocks.
        return 1 if self.active else 0
