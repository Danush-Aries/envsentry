"""Machine-readable JSON report for CI ingestion (``--format json``)."""

from __future__ import annotations

import json

from .. import __version__
from ..models import Finding, Report


def _finding_dict(f: Finding, show: bool) -> dict:
    d = {
        "detector": f.detector_id,
        "path": f.path,
        "line": f.line,
        "col": f.col,
        "confidence": f.confidence.value,
        "severity": f.severity.value,
        "redacted": f.redacted,
        "fingerprint": f.fingerprint,
        "suppressed": f.suppressed,
        "suppressed_by": f.suppressed_by,
    }
    if show:
        d["token"] = f.secret.token
    return d


def to_json(report: Report, show: bool = False) -> str:
    payload = {
        "tool": "envsentry",
        "version": __version__,
        "scanned_paths": report.scanned_paths,
        "summary": {
            "verified": len(report.verified),
            "possible": len(report.possible),
            "suppressed": len(report.suppressed),
            "total": len(report.findings),
        },
        "findings": [_finding_dict(f, show) for f in report.findings],
    }
    return json.dumps(payload, indent=2)
