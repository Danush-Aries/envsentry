"""Git integration — pure subprocess wrappers, zero external git library, offline.

Provides staged-diff parsing (added lines only), a file walker for ``audit``, and
idempotent pre-commit hook install/uninstall.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

HOOK_MARKER = "# >>> envsentry managed hook (do not edit this line) >>>"
HOOK_END = "# <<< envsentry managed hook <<<"

HOOK_SCRIPT = f"""#!/bin/sh
{HOOK_MARKER}
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
{HOOK_END}
"""

_MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB


class GitError(RuntimeError):
    """Any operational git failure (not a repo, git missing, ...) → CLI exit 2."""


@dataclass(frozen=True)
class DiffLine:
    path: str
    line: int  # 1-based line number in the new file
    text: str  # the added line content (without leading '+')


def _run(args: list[str], cwd: str | Path | None = None) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:  # git not installed
        raise GitError("git executable not found on PATH") from e
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def repo_root(cwd: str | Path | None = None) -> Path:
    out = _run(["rev-parse", "--show-toplevel"], cwd=cwd)
    return Path(out.strip())


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_diff(diff_text: str) -> list[DiffLine]:
    """Parse ``git diff --cached --unified=0`` output → added lines only."""
    out: list[DiffLine] = []
    cur_path: str | None = None
    new_lineno = 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            if target == "/dev/null":
                cur_path = None
            else:
                cur_path = target[2:] if target.startswith("b/") else target
            continue
        if raw.startswith("--- "):
            continue
        m = _HUNK.match(raw)
        if m:
            new_lineno = int(m.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            if cur_path is not None:
                out.append(DiffLine(cur_path, new_lineno, raw[1:]))
                new_lineno += 1
            continue
        if raw.startswith("-") or raw.startswith("\\"):
            # removed line / "no newline" marker: do not advance new-file counter.
            continue
        if raw.startswith(" "):
            new_lineno += 1
    return out


def staged_diff(cwd: str | Path | None = None) -> list[DiffLine]:
    diff = _run(["diff", "--cached", "--unified=0", "--no-color"], cwd=cwd)
    return parse_diff(diff)


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def iter_files(paths: list[str], max_bytes: int = _MAX_FILE_BYTES) -> Iterator[tuple[str, str]]:
    """Yield (path, text) for each readable text file under the given paths/dirs."""
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            files = sorted(fp for fp in p.rglob("*") if fp.is_file())
        elif p.is_file():
            files = [p]
        else:
            raise GitError(f"path not found: {raw}")
        for fp in files:
            if ".git/" in str(fp).replace("\\", "/"):
                continue
            try:
                if fp.stat().st_size > max_bytes:
                    continue
                data = fp.read_bytes()
            except OSError:
                continue
            if _looks_binary(data):
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            yield str(fp), text


def hook_path(cwd: str | Path | None = None) -> Path:
    root = repo_root(cwd)
    return root / ".git" / "hooks" / "pre-commit"


def install_hook(force: bool = False, cwd: str | Path | None = None) -> str:
    """Write ``.git/hooks/pre-commit``. Idempotent; refuses a foreign hook unless force.

    Returns a short human status string. Raises ``GitError`` on refusal.
    """
    hp = hook_path(cwd)
    hp.parent.mkdir(parents=True, exist_ok=True)
    if hp.exists():
        current = hp.read_text(encoding="utf-8", errors="replace")
        if HOOK_MARKER in current:
            hp.write_text(HOOK_SCRIPT, encoding="utf-8")
            hp.chmod(0o755)
            return "hook already managed by envsentry — refreshed"
        if not force:
            raise GitError(
                f"a foreign pre-commit hook exists at {hp}; re-run with --force to back it up"
            )
        backup = hp.with_name("pre-commit.envsentry.bak")
        backup.write_text(current, encoding="utf-8")
    hp.write_text(HOOK_SCRIPT, encoding="utf-8")
    hp.chmod(0o755)
    return f"installed pre-commit hook at {hp}"


def uninstall_hook(cwd: str | Path | None = None) -> str:
    hp = hook_path(cwd)
    if not hp.exists():
        return "no pre-commit hook present"
    current = hp.read_text(encoding="utf-8", errors="replace")
    if HOOK_MARKER not in current:
        return "pre-commit hook is not managed by envsentry — left untouched"
    backup = hp.with_name("pre-commit.envsentry.bak")
    if backup.exists():
        hp.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
        hp.chmod(0o755)
        backup.unlink()
        return "restored the backed-up pre-commit hook"
    hp.unlink()
    return "removed the envsentry pre-commit hook"
