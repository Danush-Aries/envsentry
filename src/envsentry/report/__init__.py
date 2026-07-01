"""Report rendering: text (default) and JSON."""

from __future__ import annotations

from ..models import Report
from .json_out import to_json
from .text import to_text


def render(report: Report, fmt: str = "text", show: bool = False) -> str:
    if fmt == "json":
        return to_json(report, show=show)
    return to_text(report, show=show)


__all__ = ["render", "to_json", "to_text"]
