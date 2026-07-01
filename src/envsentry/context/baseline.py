"""Hashed baseline (``.envsentry-allow``).

Stores accepted **fingerprints only** — never a secret, or any substring of one.
A fingerprint binds a finding to (detector, path, exact token), so rotating the
secret changes the fingerprint and re-surfaces the finding.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..models import Finding, Suppressor

BASELINE_FILENAME = ".envsentry-allow"


def fingerprint(finding: Finding) -> str:
    """sha256("{detector_id}:{path}:{token}") hex, truncated to 16 chars."""
    basis = f"{finding.detector_id}:{finding.path}:{finding.secret.token}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def load(path: str | Path) -> set[str]:
    """Return the set of accepted fingerprints (empty if the file is absent)."""
    p = Path(path)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return set()
    return {entry["fingerprint"] for entry in data.get("accepted", []) if "fingerprint" in entry}


def is_accepted(finding: Finding, baseline: set[str]) -> bool:
    fp = finding.fingerprint or fingerprint(finding)
    return fp in baseline


def accept(findings: list[Finding], path: str | Path) -> list[str]:
    """Append fingerprints for all given findings to the baseline file.

    Only ``fingerprint``, ``detector`` and ``path`` are persisted — no token text.
    Returns the list of fingerprints newly added.
    """
    p = Path(path)
    existing_raw: dict = {"version": 1, "accepted": []}
    if p.exists():
        try:
            existing_raw = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            existing_raw = {"version": 1, "accepted": []}
    existing = {e["fingerprint"] for e in existing_raw.get("accepted", []) if "fingerprint" in e}

    added: list[str] = []
    for f in findings:
        fp = f.fingerprint or fingerprint(f)
        if fp in existing:
            continue
        existing.add(fp)
        added.append(fp)
        existing_raw.setdefault("accepted", []).append(
            {"fingerprint": fp, "detector": f.detector_id, "path": f.path}
        )
    p.write_text(json.dumps(existing_raw, indent=2) + "\n", encoding="utf-8")
    return added


def build_baseline_suppressor(baseline: set[str]) -> Suppressor:
    """A suppressor that kills any finding whose fingerprint is in the baseline."""
    return Suppressor(
        id="baseline",
        reason="fingerprint accepted in .envsentry-allow",
        applies=lambda f: is_accepted(f, baseline),
    )
