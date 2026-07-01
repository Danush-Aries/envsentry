from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

CORPUS = Path(__file__).parent / "corpus"


@pytest.fixture
def corpus_text():
    def _read(name: str) -> str:
        # Fixtures embed a `{SPLIT}` sentinel inside secret tokens so the real
        # contiguous key is never committed (GitHub push protection blocks it);
        # strip it here so scanners see the reconstructed token.
        return (CORPUS / name).read_text(encoding="utf-8").replace("{SPLIT}", "")

    return _read


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """Initialise a throwaway git repo and return its root path."""

    def _git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    _git("init")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "test")
    return tmp_path
