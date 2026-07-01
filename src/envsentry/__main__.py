"""Enable `python -m envsentry ...` (used by the installed pre-commit hook fallback)."""

from .cli import app

if __name__ == "__main__":
    app()
