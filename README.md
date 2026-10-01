# envsentry

**A secret scanner that developers actually leave enabled.**

`envsentry` is a low-false-positive, context-aware secret scanner and git pre-commit
guard. It is built around one opinionated bet: **the unsolved problem in secret
scanning is not detection — it is alert fatigue.** gitleaks, trufflehog and
detect-secrets all reliably find AWS keys, and all three are famous for drowning
developers in false positives on UUIDs, git SHAs, lockfile hashes and
`API_KEY=your-key-here` placeholders. The predictable result: the developer runs
`git commit --no-verify`, disables the hook, and it protects nothing.

envsentry's single differentiator is **friction-free adoption through principled
false-positive reduction** — proven, not just claimed, by a CI-enforced invariant
(see below).

---

## Why it's different

1. **Two-tier confidence, surfaced everywhere.** Every finding is either
   `VERIFIED` (matched a provider-specific format regex) or `POSSIBLE` (entropy-only,
   no known format). **Commits fail by default only on `VERIFIED`.** A UUID or a
   high-entropy asset blob is `POSSIBLE` — reported for triage, but it can never
   block a commit unless you opt in with `--fail-on possible`. Entropy, the
   FP-prone path, is *structurally* demoted, not merely tuned.

2. **Context-aware suppression as a first-class layer.** A placeholder lexicon,
   variable-name context (`EXAMPLE_`, `SAMPLE_`, `FAKE_`, `TEST_`), a test/fixture/
   doc path allowlist, and structural exclusion of git SHAs / UUIDs / hashes run
   *after* detection and *before* reporting — each independently unit-tested.

3. **A hashed baseline (`.envsentry-allow`).** Accepting a known-safe finding writes
   only a `sha256` fingerprint to disk — **never the secret**. Rotating the secret
   changes the fingerprint and re-surfaces the finding.

4. **Zero network, ever.** No live credential verification, no telemetry, no update
   checks — safe in air-gapped CI and instant in a pre-commit hook.
   > **"VERIFIED" means format-valid and offline — explicitly *not* verified-live.**
   > Unlike trufflehog, envsentry never phones a provider to confirm a key is active.

### The CI-enforced FP invariant (the proof)

A committed corpus of real-world FP triggers (`tests/corpus/false_positives.txt` —
UUIDs, git SHAs, `.env.example` keys, placeholders, lockfile hashes) must yield
**zero blocking findings**, while a parallel corpus of format-valid fake keys
(`true_positives.txt`) must *all* fire. Both are asserted in `tests/test_corpus.py`
and gated in CI. A change that raises the corpus FP rate above zero fails the build —
so the low-false-positive property cannot silently regress.

---

## Install

```bash
pipx install git+https://github.com/Danush-Aries/envsentry   # recommended (not on PyPI yet)
# or, from a clone
pip install -e .
```

Runtime dependency is `typer` only (`rich` for optional color); everything else —
regex, entropy, hashing, git via subprocess — is the Python standard library.

## Quickstart

```bash
cd your-repo
envsentry install-hook        # writes .git/hooks/pre-commit
# ...now every commit is checked; VERIFIED secrets block, POSSIBLE ones don't.

envsentry scan                # scan the current staged diff by hand
envsentry audit src/          # scan an arbitrary tree (CI full-scan)
```

## Commands

| Command | What it does |
|---------|--------------|
| `envsentry scan` | Scan the staged git diff (the pre-commit path). Added lines only. |
| `envsentry audit PATH...` | Scan arbitrary files/dirs — CI full-tree or ad-hoc review. |
| `envsentry install-hook` | Install the managed `.git/hooks/pre-commit` (idempotent; `--force` to back up a foreign hook). |
| `envsentry uninstall-hook` | Remove the hook (restores a backed-up one if present). |
| `envsentry baseline` | Accept currently-active findings into `.envsentry-allow` (fingerprints only). `--dry-run` to preview. |
| `envsentry version` | Print the version. |

### Key flags

```
--fail-on [verified|possible|any]   default verified — only VERIFIED blocks
--format  [text|json]               json for CI ingestion
--show                              reveal full tokens (default: redacted)
--entropy-b64 FLOAT (default 4.5)   --entropy-hex FLOAT (default 3.0)
--allow-path GLOB                   extra path-allowlist glob (repeatable)
--no-baseline                       ignore .envsentry-allow
--quiet                             suppress the report, keep the exit code (hook mode)
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no blocking findings (or all suppressed / baselined). |
| `1` | Blocking findings exist per `--fail-on`. |
| `2` | Operational error (not a git repo, bad path, unreadable file). |

## Detectors

12 provider detectors (all `VERIFIED`) + 1 generic Shannon-entropy detector (`POSSIBLE`):

AWS Access Key ID · AWS Secret Access Key (keyword + entropy gated) · GitHub PAT ·
GitHub fine-grained PAT · Slack bot/user token · Stripe live secret · Stripe test
secret · Google API key · Google OAuth client ID · JWT (header must base64/JSON-decode
to `{"alg":...}`) · PEM private-key block · Slack webhook.

Every detector ships with a paired positive + negative test, so adding or updating
one is a localized change with a mandatory true-positive and false-positive assertion.

## Configuration

- **`.envsentry-allow`** — hashed baseline at repo root. Written by `envsentry baseline`;
  contains fingerprints only.
- **`--allow-path`** — extend the test/fixture/doc path allowlist.
- **`--entropy-b64` / `--entropy-hex`** — tune the `POSSIBLE` entropy thresholds.

## Development

```bash
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/pytest -q
.venv/bin/ruff check src tests
```

CI runs the suite on Python 3.10 / 3.11 / 3.12, plus `ruff check`,
`ruff format --check`, and the zero-blocking-false-positive corpus gate.

## License

MIT © 2026 Dhanush Shankar
