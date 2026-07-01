# envsentry — Implementation Plan

> A low-false-positive, context-aware secret scanner + git pre-commit guard.
> Python 3.10+ · `typer` CLI · fully offline · MIT · target v0.1.0

---

## 1. Context — the real unmet need

Secret scanning is a solved *detection* problem and an unsolved *adoption* problem. gitleaks, trufflehog, and detect-secrets all reliably find AWS keys — and all three are famous for **drowning developers in false positives**. The well-documented pain:

- **detect-secrets** ships a plugin architecture whose generic `HighEntropyString`/`KeywordDetector` plugins flag hashes, UUIDs, base64 asset blobs, lockfile integrity hashes, and minified JS constantly. Teams end up maintaining a large `.secrets.baseline` and running an interactive `audit` just to silence noise.
- **gitleaks** entropy rules + broad generic regexes fire on test fixtures, example configs, and documentation (`API_KEY=your-key-here`), forcing sprawling `.gitleaksignore` and per-rule `allowlist` regex stanzas in `.gitleaks.toml`.
- **trufflehog** leans on live credential *verification* (network calls to the provider) to cut FPs — powerful, but it phones home, needs network in CI, and does nothing for the offline pre-commit path where a developer is about to commit a *format-valid but inactive* key.

The consequence is predictable and repeatedly reported by security teams: **developers disable the hook.** A scanner that cries wolf on every UUID gets `--no-verify`'d within a week, and then it protects nothing. Alert fatigue is the actual failure mode, not detection recall.

### Honest differentiation

envsentry does **not** try to beat gitleaks/trufflehog on raw recall or on exotic provider coverage. Its single, opinionated bet is **friction-free adoption through principled false-positive reduction**:

1. **Two-tier confidence, surfaced everywhere.** Every finding is `VERIFIED` (matched a provider-specific high-confidence format regex, optionally with a checksum) or `POSSIBLE` (entropy-only, no known format). The commit **fails by default only on `VERIFIED`**. `POSSIBLE` findings are reported for human triage but never block. This is the core UX difference: developers are never blocked by a UUID.
2. **Context-aware suppression as a first-class layer**, not an afterthought regex-ignore file. Placeholder lexicon, variable-name context (`EXAMPLE_`, `SAMPLE_`, `FAKE_`), test/fixture path allowlist, and structural exclusion of git SHAs / UUIDs run *after* detection and *before* reporting, each independently unit-tested for suppression.
3. **A hashed baseline (`.envsentry-allow`)** that accepts *findings* (by stable fingerprint), not raw secrets — so accepting a finding never writes the secret to disk, and rotating the secret invalidates the acceptance.
4. **Zero network.** Unlike trufflehog verification, envsentry is deterministic and offline — safe in air-gapped CI and instant in a pre-commit hook. "VERIFIED" here means *verified format*, explicitly not *verified-live*, and the docs say so.

The measurable thesis: **on a corpus of real-world FP triggers (UUIDs, git SHAs, `.env.example` files, lockfile hashes, docs placeholders) envsentry emits zero blocking findings, while still catching format-valid fake keys.** That property is what keeps the hook enabled, and it is enforced by the test suite (section 7).

---

## 2. Architecture — modules for parallel builders

Designed so **3–4 builder subagents work non-overlapping modules** against a frozen shared contract (`models.py`, section 3). Only `cli.py` and `report/` import broadly; everything else depends solely on `models.py`.

```
envsentry/
├── __init__.py            # __version__ = "0.1.0"
├── models.py              # SHARED CONTRACT — dataclasses + enums (build FIRST, then freeze)
├── detectors/
│   ├── __init__.py        # DETECTORS registry: list[Detector], entropy detector factory
│   ├── providers.py       # 12 provider regex Detectors (AWS, GitHub, Slack, Stripe, ...)
│   └── entropy.py         # Shannon-entropy generic detector (base64/hex tokenizer)
├── context/
│   ├── __init__.py        # apply_suppressors(findings, ctx) -> findings (sets suppressed flag)
│   ├── suppressors.py      # placeholder / varname / path / structural (sha,uuid) suppressors
│   └── baseline.py        # .envsentry-allow read/write, fingerprinting, accept()
├── git.py                 # staged diff parsing, added-line extraction, hook install/uninstall
├── report/
│   ├── __init__.py        # build_report(findings) -> Report
│   ├── text.py            # human-readable terminal output (grouped by confidence)
│   └── json_out.py        # machine JSON (--format json) for CI ingestion
├── cli.py                 # typer app: scan / audit / install-hook / baseline / version
└── scanner.py             # orchestration glue: bytes/lines -> detectors -> context -> findings
```

### Builder assignment (parallel-safe)

| Builder | Owns | Depends on | Cannot touch |
|---------|------|-----------|--------------|
| **A — Detectors** | `detectors/providers.py`, `detectors/entropy.py`, `detectors/__init__.py` | `models.py` | context/, git/, cli |
| **B — Context/FP** | `context/suppressors.py`, `context/baseline.py`, `context/__init__.py` | `models.py` | detectors/, git/, cli |
| **C — Git + Report** | `git.py`, `report/*` | `models.py` | detectors/, context/ |
| **D — CLI + Scanner glue** | `cli.py`, `scanner.py`, `__init__.py`, packaging | `models.py` + public fns of A/B/C | internal helpers of others |

`models.py` is authored and frozen **before** fan-out (Phase P0). Each builder owns its own `tests/` files (section 7) so test files never collide. `scanner.py` and `cli.py` are the only integration points — assigned to Builder D last, after A/B/C expose their documented public functions.

---

## 3. Shared data contract (`models.py`)

Frozen before any parallel work. Standard-library only (`dataclasses`, `enum`, `re`, `typing`). No third-party types leak into the contract.

```python
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Pattern, Optional

class Confidence(str, Enum):
    VERIFIED = "verified"   # matched a provider format regex (+ optional checksum)
    POSSIBLE = "possible"   # entropy-only; no known provider format

class Severity(str, Enum):
    HIGH = "high"           # live-cred-class providers (AWS, Stripe live, private key)
    MEDIUM = "medium"       # tokens, generic entropy
    LOW = "low"

@dataclass(frozen=True)
class Detector:
    """A single detection rule. Pure/deterministic; no I/O."""
    id: str                         # "aws-access-key-id"
    name: str                       # "AWS Access Key ID"
    confidence: Confidence          # VERIFIED for provider regex, POSSIBLE for entropy
    severity: Severity
    pattern: Optional[Pattern]      # compiled regex; None for the entropy detector
    # find(line) yields (matched_token, start_col, end_col) tuples
    find: Callable[[str], list[tuple[str, int, int]]]
    # optional secondary validator (e.g. AWS secret-key entropy, Luhn, base64 sanity)
    validate: Optional[Callable[[str], bool]] = None

@dataclass(frozen=True)
class Secret:
    """A raw candidate located in source before context filtering."""
    detector_id: str
    token: str                      # the matched substring (never logged in full by report)
    confidence: Confidence
    severity: Severity

@dataclass
class Finding:
    """A Secret placed in file/line context, post-detection, pre/post-suppression."""
    secret: Secret
    path: str                       # file path or "<staged>"
    line: int                       # 1-based
    col: int                        # 1-based column of token start
    line_text: str                  # full source line (for --show; redacted in default output)
    suppressed: bool = False
    suppressed_by: Optional[str] = None   # suppressor id that killed it
    fingerprint: str = ""           # stable hash; computed by baseline layer

    @property
    def redacted(self) -> str: ...  # token -> first4 + "…" + last2, or "****" if short

@dataclass(frozen=True)
class Suppressor:
    """A context rule that may mark a Finding as suppressed."""
    id: str                         # "placeholder", "varname-example", "path-allowlist", ...
    reason: str
    # returns True if this finding should be suppressed
    applies: Callable[[Finding], bool]

@dataclass
class Report:
    findings: list[Finding]         # ALL findings (suppressed + active)
    scanned_paths: list[str]
    @property
    def active(self) -> list[Finding]: ...      # not suppressed, not baselined
    @property
    def verified(self) -> list[Finding]: ...    # active AND Confidence.VERIFIED
    @property
    def possible(self) -> list[Finding]: ...    # active AND Confidence.POSSIBLE
    @property
    def suppressed(self) -> list[Finding]: ...
    def exit_code(self, fail_on: Confidence = Confidence.VERIFIED) -> int: ...
```

**Fingerprint** (used by baseline, computed in `context/baseline.py`):
`sha256(f"{detector_id}:{path}:{normalized_token}")` hex, truncated to 16 chars. Normalized token = the raw secret, so rotating the secret changes the fingerprint and re-surfaces it. Path is included so the same key in two files is triaged separately.

---

## 4. Detector catalog (`detectors/`)

12 provider detectors (all `Confidence.VERIFIED`) + 1 generic entropy detector (`Confidence.POSSIBLE`). Each detector is a `Detector` dataclass registered in `DETECTORS`. Every detector ships with **paired unit tests: at least one true-positive and at least one placeholder/negative** to prove low FP.

| # | id | Format regex (anchored to token boundaries) | Sev | Positive test | Negative / FP test |
|---|-----|----------|-----|---------------|--------------------|
| 1 | `aws-access-key-id` | `\b(AKIA\|ASIA)[0-9A-Z]{16}\b` | HIGH | `AKIAIOSFODNN7EXAMPLE` triggers | `AKIA` + lowercase / 10 chars must NOT |
| 2 | `aws-secret-access-key` | `\b[A-Za-z0-9/+=]{40}\b` **+ validate: entropy>4.0 AND near `aws`/`secret` keyword** | HIGH | 40-char high-entropy near `aws_secret` | 40-char git-tree-ish low entropy must NOT |
| 3 | `github-pat` | `\bghp_[A-Za-z0-9]{36}\b` (also `gho_`,`ghu_`,`ghs_`,`ghr_`) | HIGH | `ghp_` + 36 alnum triggers | `ghp_xxxxxxxx...` placeholder must NOT (via context) |
| 4 | `github-fine-grained-pat` | `\bgithub_pat_[A-Za-z0-9_]{82}\b` | HIGH | valid-length token | short token must NOT |
| 5 | `slack-bot-token` | `\bxox[baprs]-[0-9A-Za-z-]{10,48}\b` | HIGH | `xoxb-...` triggers | `xoxb-your-token` placeholder suppressed |
| 6 | `stripe-secret-live` | `\bsk_live_[0-9A-Za-z]{24,}\b` | HIGH | `sk_live_...` triggers | `sk_test_...` is separate lower sev; `sk_live_xxxx` suppressed |
| 7 | `stripe-secret-test` | `\bsk_test_[0-9A-Za-z]{24,}\b` | MEDIUM | `sk_test_...` triggers (medium) | doc example suppressed by path/placeholder |
| 8 | `google-api-key` | `\bAIza[0-9A-Za-z\-_]{35}\b` | HIGH | `AIza` + 35 triggers | `AIzaSyEXAMPLE...`-with-`EXAMPLE` suppressed |
| 9 | `google-oauth-id` | `\b[0-9]{12}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b` | MEDIUM | valid client id triggers | truncated must NOT |
| 10 | `jwt` | `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b` **+ validate: header decodes to `{"alg"...}`** | MEDIUM | real 3-part JWT triggers | `eyJ...` that fails base64/JSON decode must NOT |
| 11 | `private-key-block` | `-----BEGIN (RSA\|EC\|OPENSSH\|DSA\|PGP\|PRIVATE) ?(PRIVATE )?KEY-----` (multiline-aware) | HIGH | PEM header triggers | `-----BEGIN CERTIFICATE-----` (public) must NOT |
| 12 | `slack-webhook` | `\bhttps://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+\b` | MEDIUM | full webhook triggers | bare `hooks.slack.com` must NOT |

### Generic entropy detector (`detectors/entropy.py`) — `Confidence.POSSIBLE`

- **Tokenizer**: split each line on non-`[A-Za-z0-9+/=_\-]` chars; keep tokens length ≥ 20.
- **Charset classification**: base64-ish (`[A-Za-z0-9+/=]`) or hex (`[0-9a-fA-F]`) or generic.
- **Shannon entropy** `H = -Σ p(c) log2 p(c)` over the token's characters.
- **Thresholds** (tunable via `--entropy-b64` / `--entropy-hex`, defaults chosen from empirical FP corpus):
  - base64 token: flag if `len ≥ 20` **and** `H ≥ 4.5`.
  - hex token: flag if `len ≥ 32` **and** `H ≥ 3.0`.
- **Emits `POSSIBLE` only** → never blocks a commit by default. This is deliberate: entropy is the FP-prone path, so it is structurally demoted, not merely tuned.
- **Structural pre-exclusion** (before emitting, cheap): pure lowercase 40-hex (git SHA-1), 64-hex (SHA-256), and canonical UUID are dropped here *and* also caught by the structural suppressor (defense in depth).

**Entropy tests**: (a) a 32-char random base64 secret triggers POSSIBLE; (b) an English sentence of the same length does NOT; (c) a git SHA-1 does NOT; (d) a UUID does NOT; (e) a base64-encoded PNG chunk of low-entropy repetition does NOT; (f) threshold boundary: token at `H = 4.49` excluded, `H = 4.51` included.

---

## 5. Context / false-positive reduction (`context/`)

`apply_suppressors(findings, ctx)` runs each `Suppressor` over every `Finding`; the first matching suppressor sets `suppressed=True` and `suppressed_by=<id>`. Order matters only for attribution, not correctness.

### Suppressors (`context/suppressors.py`)

1. **`placeholder`** — token or its line matches a curated lexicon (case-insensitive): `xxxx+`, `changeme`, `example`, `dummy`, `placeholder`, `redacted`, `your[-_]?key`, `<...>` angle-bracket templates, `0000+`, `1234...`, `deadbeef`, `foobar`, all-same-char runs, `insert.*here`. Tested: `AKIA0000000000000000` and `sk_live_` followed by 24 `x`s suppressed; a real-looking token NOT suppressed.
2. **`varname-example`** — the assignment target on the line starts with / contains `EXAMPLE_`, `SAMPLE_`, `FAKE_`, `TEST_`, `DUMMY_`, `MOCK_` (regex on `^\s*([A-Z0-9_]*?(EXAMPLE|SAMPLE|FAKE|DUMMY|MOCK)[A-Z0-9_]*)\s*[:=]`). Tested: `EXAMPLE_API_KEY=AIza...` suppressed; `PROD_API_KEY=AIza...` NOT.
3. **`path-allowlist`** — file path matches test/fixture/doc globs: `**/test/**`, `**/tests/**`, `**/__tests__/**`, `**/fixtures/**`, `**/testdata/**`, `*.example`, `*.sample`, `*.md`, `*.rst`, `**/examples/**`, `.env.example`, `.env.sample`, `**/mocks/**`. Configurable/extendable via `--allow-path`. Tested: finding in `tests/fixtures/keys.txt` suppressed; same in `src/config.py` NOT. **HIGH-severity VERIFIED findings honor path-allowlist too but are additionally listed in a "suppressed (allowlisted path)" section so a real leak in a test file isn't silently invisible.**
4. **`structural`** — token is a git SHA (`^[0-9a-f]{7,40}$` all-lower), SHA-256 (`^[0-9a-f]{64}$`), UUID (`^[0-9a-fA-F]{8}-...-[0-9a-fA-F]{12}$`), or ISO timestamp / integer sequence. Tested: a 40-hex SHA and a UUID suppressed; a mixed-case 40-char high-entropy secret NOT.
5. **`baseline`** — see below; suppresses any finding whose fingerprint is in `.envsentry-allow`.

Suppressors 1–4 are pure functions of a `Finding`; suppressor 5 closes over the loaded baseline set. All are exported as `Suppressor` instances in a `SUPPRESSORS` list plus a `build_baseline_suppressor(baseline)` factory.

### Baseline (`context/baseline.py`)

- **File**: `.envsentry-allow` at repo root — a JSON (or simple `fingerprint  # detector_id path` line) list of accepted **fingerprints only** (no secrets on disk, ever).
- **`load(path) -> set[str]`**, **`accept(findings, path)`** appends fingerprints for all *currently active* findings, **`is_accepted(finding, baseline) -> bool`**.
- **`fingerprint(finding) -> str`** (the sha256 recipe in section 3) — the single source of truth, imported by the baseline suppressor and by `envsentry baseline`.
- Tests: a finding present in baseline is suppressed with `suppressed_by="baseline"`; after the secret's token changes, fingerprint changes and it re-surfaces (rotation test).

---

## 6. Git integration (`git.py`)

Pure subprocess wrappers around `git`, no external git library (offline, zero deps).

- **`staged_diff() -> list[DiffLine]`**: runs `git diff --cached --unified=0 --no-color`; parses hunks; returns **only added lines** (`+` not `+++`) with their target file path and 1-based new-file line number. Handles binary-file skips, renames, and file deletions.
- **`repo_root() -> Path`**: `git rev-parse --show-toplevel`; raises a clean error (→ exit 2) outside a repo.
- **`iter_files(paths) -> Iterator[(path, text)]`**: for `audit`, walks paths, skips binary (null-byte sniff) and files > configurable size (default 5 MB), respects `.gitignore` opt-in via `--respect-gitignore`.
- **`install_hook(force: bool)`**: writes `.git/hooks/pre-commit`. If a hook exists and isn't ours → refuse unless `--force`; if `--force`, back it up to `pre-commit.envsentry.bak`. Marks file `chmod +x`. Idempotent (detects our marker comment).
- **`uninstall_hook()`**: restores backup if present, else removes our hook.

### Installed pre-commit hook script (exact behavior)

```sh
#!/bin/sh
# >>> envsentry managed hook (do not edit this line) >>>
# Blocks a commit when VERIFIED secrets appear in the staged diff.
if command -v envsentry >/dev/null 2>&1; then
    envsentry scan --staged --fail-on verified --quiet
else
    python -m envsentry scan --staged --fail-on verified --quiet
fi
status=$?
if [ "$status" -eq 1 ]; then
    echo "envsentry: VERIFIED secret(s) in staged changes — commit blocked."
    echo "Review above. To accept a known-safe finding: envsentry baseline"
    echo "To bypass once (discouraged): git commit --no-verify"
fi
exit "$status"
# <<< envsentry managed hook <<<
```

The hook **never blocks on POSSIBLE findings** (`--fail-on verified`), which is the whole adoption argument: entropy noise cannot stop a commit unless the developer opts in with `--fail-on possible`.

---

## 7. CLI surface (`cli.py`, typer)

```
envsentry scan          # scan staged git diff (default target). For the hook + local pre-commit check.
    --staged/--no-staged      (default --staged)
    --fail-on [verified|possible|any]   (default verified)
    --format [text|json]      (default text)
    --show                    reveal redacted tokens (default: redacted)
    --entropy-b64 FLOAT       (default 4.5)  --entropy-hex FLOAT (default 3.0)
    --allow-path GLOB         (repeatable)  --no-baseline  --quiet

envsentry audit PATH...  # scan arbitrary files/dirs (CI full-tree, ad-hoc review)
    (same detection/context flags as scan; walks dirs, skips binary/large)

envsentry install-hook   # write .git/hooks/pre-commit
    --force                   overwrite/back up an existing foreign hook
envsentry uninstall-hook

envsentry baseline       # accept all currently-active findings into .envsentry-allow
    --staged/--path PATH...   choose what to baseline (default staged)
    --dry-run                 show what would be accepted, write nothing

envsentry version
```

**Exit codes (contract, tested):** `0` clean/all-suppressed/all-baselined · `1` blocking findings exist per `--fail-on` · `2` operational error (not a git repo, bad path, unreadable). `--quiet` suppresses the human report but preserves exit code (hook mode).

---

## 8. Quality gate — enumerated tests (all real, no stubs)

`pytest` suite, ≥ 20 tests, organized per-module so parallel builders never edit the same test file. **The FP tests are the product's proof of value and are non-negotiable.**

**False-positive suppression (must NOT trigger a blocking finding):**
1. `test_fp_uuid_not_flagged` — canonical UUID in code → 0 active findings.
2. `test_fp_git_sha_not_flagged` — 40-hex and 7-hex SHAs → suppressed by `structural`.
3. `test_fp_sha256_hash_not_flagged` — 64-hex integrity hash → suppressed.
4. `test_fp_env_example_file` — `AIza...` in `.env.example` → suppressed by `path-allowlist`.
5. `test_fp_example_varname` — `EXAMPLE_API_KEY=AKIA...EXAMPLE` → suppressed by `varname-example`.
6. `test_fp_placeholder_tokens` — `changeme`, `<your-key>`, `xxxx`, `0000...`, `sk_live_xxxx...` → all suppressed.
7. `test_fp_english_prose_high_len` — long English sentence → entropy detector does NOT fire.
8. `test_fp_test_fixture_path` — real-format key under `tests/fixtures/` → suppressed but listed in suppressed section.
9. `test_fp_lockfile_integrity_hash` — `sha512-...` base64 in a lockfile line → not a VERIFIED finding.
10. `test_fp_corpus_zero_blocking` — a bundled `tests/corpus/false_positives.txt` (UUIDs, SHAs, placeholders, example vars) yields **0 VERIFIED active findings** (the headline metric guard).

**True-positive detection (MUST trigger):**
11. `test_tp_aws_akia` — `AKIAIOSFODNN7EXAMPLE`-style real format in `src/config.py` → 1 VERIFIED HIGH. (Note: the literal AWS-docs `EXAMPLE` string is intentionally used ONLY to confirm regex shape in a non-allowlisted path where placeholder rules are also asserted separately.)
12. `test_tp_github_pat` — `ghp_` + 36 alnum → VERIFIED.
13. `test_tp_slack_bot` — `xoxb-...` real → VERIFIED.
14. `test_tp_stripe_live` — `sk_live_...` → VERIFIED HIGH.
15. `test_tp_google_api` — `AIza` + 35 → VERIFIED.
16. `test_tp_jwt_valid_header` — JWT whose header base64-decodes to valid `{"alg":...}` → VERIFIED; malformed `eyJ...` → NOT.
17. `test_tp_private_key_block` — PEM `BEGIN OPENSSH PRIVATE KEY` → VERIFIED HIGH; `BEGIN CERTIFICATE` → NOT.
18. `test_tp_generic_entropy_possible` — random 32-char base64 secret → 1 **POSSIBLE** finding, NOT VERIFIED, does NOT block default `--fail-on verified`.

**Entropy math + thresholds:**
19. `test_entropy_shannon_value` — known string → asserted `H` to 3 decimals.
20. `test_entropy_boundary` — token at `H=4.49` excluded, `H=4.51` included (b64 path).

**Baseline:**
21. `test_baseline_suppresses` — accepted fingerprint → finding suppressed_by `baseline`.
22. `test_baseline_rotation_resurfaces` — change the token → new fingerprint → finding returns.
23. `test_baseline_writes_no_secret` — assert `.envsentry-allow` contents contain no substring of the original token.

**Git + CLI (integration, uses a temp git repo fixture):**
24. `test_staged_diff_added_lines_only` — removed lines and context ignored; only `+` added lines scanned.
25. `test_install_hook_idempotent` — install twice → single managed block; foreign hook refused without `--force`, backed up with `--force`.
26. `test_exit_codes` — clean→0, verified present→1, not-a-repo→2.
27. `test_scan_json_format` — `--format json` emits parseable JSON with confidence/severity/redacted fields and never the full token unless `--show`.

**Tooling / CI:**
- `ruff check` + `ruff format --check` clean (config in `pyproject.toml`, line-length 100).
- `mypy` (optional, non-blocking in P0; targeted at `models.py` + public fns).
- **GitHub Actions** `.github/workflows/ci.yml`: matrix Python `3.10 / 3.11 / 3.12`, steps = install (`pip install -e .[dev]`), `ruff check`, `ruff format --check`, `pytest -q`. Runs offline; no secrets/network.
- **README** outline: what/why (FP pain + verified-vs-possible), install (`pipx install envsentry`), quickstart (`envsentry install-hook`), the four commands, config (`.envsentry-allow`, allow-paths, entropy flags), detector table, FP-reduction explainer, "verified ≠ live-verified" caveat, exit codes, contributing.
- **LICENSE**: MIT.
- **Release**: tag `v0.1.0`, build sdist+wheel with `python -m build`, `pyproject.toml` metadata (classifiers, `console_scripts` entry point `envsentry = envsentry.cli:app`), CHANGELOG.

---

## 9. Offline / free-tier guarantees

- **Zero network** in every code path — no live credential verification, no telemetry, no update checks. Safe in air-gapped CI.
- **Runtime deps: `typer` only** (pulls `click`; optional `rich` for color, guarded so absence degrades to plain text). Everything else — regex, entropy, hashing, git via subprocess — is standard library.
- **Dev deps**: `pytest`, `ruff`, `build`. All PyPI-free-tier, no paid services.
- No API keys, no accounts, no Docker required.

---

## 10. Phased roadmap

- **P0 — Scaffold (serial, before fan-out).** Repo layout, `pyproject.toml`, `models.py` authored and **frozen**, `__version__`, empty module stubs with documented public signatures, ruff config, CI skeleton, MIT, README stub. Gate: `pip install -e .` works, `envsentry version` runs, `ruff check` clean.
- **P1 — Detectors (Builder A).** 12 provider regexes + entropy detector + registry. Gate: tests 11–20 pass in isolation against raw strings.
- **P2 — Context / FP-reduction + baseline (Builder B).** 5 suppressors + `.envsentry-allow`. Gate: tests 1–10, 21–23 pass. **This is the value-defining phase — corpus test #10 must show 0 blocking FPs.**
- **P3 — Git staged-diff + hook + report (Builder C).** Diff parsing, hook install, text/json report. Gate: tests 24–27 pass in a temp-repo fixture.
- **Integration (Builder D).** `scanner.py` wires detectors→context→report; `cli.py` exposes all commands; end-to-end tests green; ship.
- **Ship.** Full suite + ruff + CI matrix green on 3.10–3.12 → tag & build `v0.1.0`.

Parallelism: after P0, Builders A/B/C run **concurrently** (non-overlapping files, shared frozen `models.py`); D integrates once their public functions land.

---

## 11. Risks & differentiation — keeping the FP rate low (and proving it)

| Risk | Mitigation |
|------|-----------|
| **Entropy FPs re-introduce the noise problem envsentry exists to solve.** | Entropy findings are *structurally* `POSSIBLE` and never block by default. Boundary tests (#20) + the FP corpus test (#10) lock thresholds. Changing a default that raises corpus FPs above 0 fails CI. |
| **"VERIFIED" misread as "live/active credential."** | Docs + `--help` state VERIFIED = *format-valid, offline*. Explicit contrast with trufflehog live verification in README. |
| **Path-allowlist hides a real leak in a test dir.** | Allowlisted HIGH-severity VERIFIED findings are still *reported* in a "suppressed (allowlisted)" section, just not blocking — visible, not silent. |
| **Baseline drift / secret written to disk.** | Baseline stores only fingerprints (sha256), asserted by test #23; rotation invalidates acceptance (test #22). |
| **Provider format drift (GitHub token length changes, new prefixes).** | Detectors are data-driven `Detector` entries with paired tests; adding/updating one is a localized change with a mandatory positive+negative test. |
| **False negatives (we under-detect to look clean).** | True-positive suite (#11–18) guards recall on canonical formats; entropy backstop catches unknown-format high-entropy tokens as POSSIBLE. |

### The FP-rate discipline (the differentiator, operationalized)

- A committed, growing **`tests/corpus/false_positives.txt`** of real-world FP triggers is the regression harness. **Metric: 0 blocking (VERIFIED, non-suppressed) findings on the corpus** — enforced by test #10 in CI on every PR.
- A parallel **`tests/corpus/true_positives.txt`** of fake-but-format-valid keys guards recall (must all fire).
- New detectors/suppressors may only merge if both corpus tests stay green — so the FP-reduction property can't silently regress. That CI-enforced invariant is what lets a developer trust the hook enough to leave it on, which is the entire reason envsentry exists.
