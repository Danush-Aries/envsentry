"""Context layer: apply suppressors + baseline to findings."""

from __future__ import annotations

from ..models import Finding, Suppressor
from .baseline import (
    BASELINE_FILENAME,
    accept,
    build_baseline_suppressor,
    fingerprint,
    is_accepted,
    load,
)
from .suppressors import default_suppressors


def apply_suppressors(findings: list[Finding], suppressors: list[Suppressor]) -> list[Finding]:
    """Mark each finding suppressed by the FIRST matching suppressor. Mutates in place."""
    for f in findings:
        if f.suppressed:
            continue
        for s in suppressors:
            if s.applies(f):
                f.suppressed = True
                f.suppressed_by = s.id
                break
    return findings


__all__ = [
    "BASELINE_FILENAME",
    "accept",
    "apply_suppressors",
    "build_baseline_suppressor",
    "default_suppressors",
    "fingerprint",
    "is_accepted",
    "load",
]
