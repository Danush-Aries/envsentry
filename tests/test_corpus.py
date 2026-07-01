"""Corpus invariants (plan test 10 + recall guard).

The headline metric: on a corpus of real-world FP triggers, envsentry emits ZERO
blocking (VERIFIED, active) findings — while still catching every format-valid
fake key in the true-positive corpus. Both are CI-enforced here.
"""

from __future__ import annotations

from envsentry.scanner import scan_text

# Non-allowlisted path on purpose: the corpus must be silenced by CONTENT-aware
# suppressors (placeholder / varname / structural / entropy-demotion), not merely
# because it lives under tests/.
_FP_PATH = "src/production_app.py"
_TP_PATH = "src/production_app.py"

_EXPECTED_TP = {
    "aws-access-key-id",
    "github-pat",
    "slack-bot-token",
    "stripe-secret-live",
    "google-api-key",
    "jwt",
    "private-key-block",
}


def test_fp_corpus_zero_blocking(corpus_text):
    report = scan_text(_FP_PATH, corpus_text("false_positives.txt"))
    assert report.verified == [], [(f.detector_id, f.line, f.redacted) for f in report.verified]


def test_tp_corpus_full_recall(corpus_text):
    report = scan_text(_TP_PATH, corpus_text("true_positives.txt"))
    fired = {f.detector_id for f in report.verified}
    missing = _EXPECTED_TP - fired
    assert not missing, f"true-positive corpus missed: {missing}"
