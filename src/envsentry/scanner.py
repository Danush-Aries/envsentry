"""Orchestration glue: text/lines -> detectors -> context -> Report.

The only place (besides cli/report) that imports broadly. Everything upstream
depends solely on ``models.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .context import apply_suppressors, build_baseline_suppressor, default_suppressors, fingerprint
from .context import load as load_baseline
from .detectors import all_detectors
from .git import DiffLine, iter_files, staged_diff
from .models import Confidence, Detector, Finding, Report, Secret, Suppressor

STAGED_PATH = "<staged>"


@dataclass
class ScanConfig:
    entropy_b64: float = 4.5
    entropy_hex: float = 3.0
    allow_globs: tuple[str, ...] = ()
    use_baseline: bool = True
    baseline_path: str | None = None


def _detect_line(path: str, line_no: int, text: str, detectors: list[Detector]) -> list[Finding]:
    findings: list[Finding] = []
    verified_spans: list[tuple[int, int]] = []
    for det in detectors:
        for tok, start, end in det.find(text):
            secret = Secret(det.id, tok, det.confidence, det.severity)
            findings.append(Finding(secret, path, line_no, start + 1, text))
            if det.confidence is Confidence.VERIFIED:
                verified_spans.append((start, end))
    # De-dup: drop a POSSIBLE (entropy) hit that overlaps a VERIFIED provider match
    # on the same line — the provider finding already covers it.
    if verified_spans:
        kept: list[Finding] = []
        for f in findings:
            if f.confidence is Confidence.POSSIBLE:
                s = f.col - 1
                e = s + len(f.secret.token)
                if any(s < ve and e > vs for vs, ve in verified_spans):
                    continue
            kept.append(f)
        findings = kept
    return findings


def _build_suppressors(cfg: ScanConfig) -> list[Suppressor]:
    suppressors = default_suppressors(cfg.allow_globs)
    if cfg.use_baseline and cfg.baseline_path:
        baseline = load_baseline(cfg.baseline_path)
        suppressors.append(build_baseline_suppressor(baseline))
    return suppressors


def _finalize(findings: list[Finding], paths: list[str], cfg: ScanConfig) -> Report:
    for f in findings:
        f.fingerprint = fingerprint(f)
    apply_suppressors(findings, _build_suppressors(cfg))
    return Report(findings=findings, scanned_paths=paths)


def scan_text(path: str, text: str, cfg: ScanConfig | None = None) -> Report:
    """Scan a single in-memory document."""
    cfg = cfg or ScanConfig()
    detectors = all_detectors(cfg.entropy_b64, cfg.entropy_hex)
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        findings.extend(_detect_line(path, i, line, detectors))
    return _finalize(findings, [path], cfg)


def scan_paths(paths: list[str], cfg: ScanConfig | None = None) -> Report:
    """Scan files/dirs on disk (the ``audit`` command)."""
    cfg = cfg or ScanConfig()
    detectors = all_detectors(cfg.entropy_b64, cfg.entropy_hex)
    findings: list[Finding] = []
    scanned: list[str] = []
    for path, text in iter_files(paths):
        scanned.append(path)
        for i, line in enumerate(text.splitlines(), start=1):
            findings.extend(_detect_line(path, i, line, detectors))
    return _finalize(findings, scanned, cfg)


def scan_staged(cfg: ScanConfig | None = None, diff_lines: list[DiffLine] | None = None) -> Report:
    """Scan the staged git diff (added lines only)."""
    cfg = cfg or ScanConfig()
    detectors = all_detectors(cfg.entropy_b64, cfg.entropy_hex)
    lines = diff_lines if diff_lines is not None else staged_diff()
    findings: list[Finding] = []
    for dl in lines:
        findings.extend(_detect_line(dl.path, dl.line, dl.text, detectors))
    return _finalize(findings, sorted({dl.path for dl in lines}), cfg)
