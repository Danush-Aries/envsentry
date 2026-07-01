"""Human-readable terminal report, grouped by confidence tier."""

from __future__ import annotations

from ..models import Finding, Report


def _line(f: Finding, show: bool) -> str:
    token = f.secret.token if show else f.redacted
    return f"  {f.path}:{f.line}:{f.col}  [{f.severity.value:6}] {f.detector_id}  {token}"


def to_text(report: Report, show: bool = False) -> str:
    out: list[str] = []
    verified = report.verified
    possible = report.possible
    suppressed = report.suppressed

    if verified:
        out.append(f"VERIFIED — blocking ({len(verified)}):")
        out.extend(_line(f, show) for f in verified)
        out.append("")
    if possible:
        out.append(f"POSSIBLE — review, non-blocking ({len(possible)}):")
        out.extend(_line(f, show) for f in possible)
        out.append("")

    allowlisted_high = [
        f for f in suppressed if f.suppressed_by == "path-allowlist" and f.severity.value == "high"
    ]
    if allowlisted_high:
        out.append(
            f"SUPPRESSED (allowlisted path — visible, not blocking) ({len(allowlisted_high)}):"
        )
        out.extend(_line(f, show) for f in allowlisted_high)
        out.append("")

    if not verified and not possible:
        out.append("No active findings. Clean.")

    out.append(
        f"summary: {len(verified)} verified, {len(possible)} possible, "
        f"{len(suppressed)} suppressed, {len(report.findings)} total"
    )
    return "\n".join(out)
