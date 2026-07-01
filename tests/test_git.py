"""Git staged-diff parsing + hook install tests (plan tests 24-25)."""

from __future__ import annotations

from pathlib import Path

import pytest

from envsentry import git
from envsentry.git import HOOK_MARKER, GitError, parse_diff
from envsentry.scanner import scan_staged

_DIFF = """diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -2 +2 @@
-KEY = "old-value-removed"
+AWS = "AKIAIOSFODNN7EXAMPLE"
@@ -5,0 +6 @@
+SAFE = "just some prose here"
"""


def test_staged_diff_added_lines_only():
    lines = parse_diff(_DIFF)
    # removed line ignored; only the two '+' added lines are returned.
    assert [dl.text for dl in lines] == [
        'AWS = "AKIAIOSFODNN7EXAMPLE"',
        'SAFE = "just some prose here"',
    ]
    assert lines[0].path == "config.py"
    assert lines[0].line == 2
    assert lines[1].line == 6

    report = scan_staged(diff_lines=lines)
    assert len(report.verified) == 1
    assert report.verified[0].line == 2


def test_install_hook_idempotent(tmp_git_repo: Path):
    git.install_hook(cwd=tmp_git_repo)
    hook = tmp_git_repo / ".git" / "hooks" / "pre-commit"
    text = hook.read_text()
    assert text.count(HOOK_MARKER) == 1
    assert hook.stat().st_mode & 0o111  # executable

    git.install_hook(cwd=tmp_git_repo)  # twice -> still a single managed block
    assert hook.read_text().count(HOOK_MARKER) == 1


def test_install_hook_refuses_foreign_without_force(tmp_git_repo: Path):
    hook = tmp_git_repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho custom\n")

    with pytest.raises(GitError):
        git.install_hook(cwd=tmp_git_repo)

    git.install_hook(force=True, cwd=tmp_git_repo)
    backup = tmp_git_repo / ".git" / "hooks" / "pre-commit.envsentry.bak"
    assert backup.exists() and "echo custom" in backup.read_text()
    assert HOOK_MARKER in hook.read_text()


def test_repo_root_outside_repo_raises(tmp_path: Path):
    with pytest.raises(GitError):
        git.repo_root(cwd=tmp_path)
