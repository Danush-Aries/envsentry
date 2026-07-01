"""envsentry CLI (typer).

    envsentry scan            # scan the staged git diff (pre-commit path)
    envsentry audit PATH...   # scan arbitrary files/dirs (CI full-tree, ad-hoc)
    envsentry install-hook    # write .git/hooks/pre-commit
    envsentry uninstall-hook
    envsentry baseline        # accept currently-active findings into .envsentry-allow
    envsentry version

Exit codes: 0 clean/all-suppressed · 1 blocking findings per --fail-on · 2 error.
VERIFIED means format-valid + offline — explicitly NOT verified-live.
"""

from __future__ import annotations

from pathlib import Path

import typer

from . import __version__, git, scanner
from .context import BASELINE_FILENAME, accept
from .git import GitError
from .models import Confidence, Report
from .report import render
from .scanner import ScanConfig

app = typer.Typer(
    add_completion=False,
    help="Low-false-positive, context-aware secret scanner + git pre-commit guard.",
)


def _fail_on(value: str) -> Confidence:
    v = value.strip().lower()
    if v in ("verified",):
        return Confidence.VERIFIED
    if v in ("possible", "any"):
        return Confidence.POSSIBLE
    raise typer.BadParameter("--fail-on must be one of: verified | possible | any")


def _config(
    entropy_b64: float,
    entropy_hex: float,
    allow_path: list[str] | None,
    no_baseline: bool,
    baseline_path: str | None,
) -> ScanConfig:
    return ScanConfig(
        entropy_b64=entropy_b64,
        entropy_hex=entropy_hex,
        allow_globs=tuple(allow_path or ()),
        use_baseline=not no_baseline,
        baseline_path=baseline_path,
    )


def _default_baseline_path() -> str:
    try:
        return str(git.repo_root() / BASELINE_FILENAME)
    except GitError:
        return BASELINE_FILENAME


def _emit(report: Report, fmt: str, show: bool, quiet: bool, fail_on: Confidence) -> None:
    if not quiet:
        typer.echo(render(report, fmt, show=show))
    raise typer.Exit(report.exit_code(fail_on))


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"envsentry {__version__}")


@app.command()
def scan(
    staged: bool = typer.Option(True, "--staged/--no-staged", help="scan the staged git diff"),
    fail_on: str = typer.Option("verified", "--fail-on", help="verified | possible | any"),
    format: str = typer.Option("text", "--format", "-f", help="text | json"),
    show: bool = typer.Option(False, "--show", help="reveal full tokens (default: redacted)"),
    entropy_b64: float = typer.Option(4.5, "--entropy-b64", help="base64 entropy threshold"),
    entropy_hex: float = typer.Option(3.0, "--entropy-hex", help="hex entropy threshold"),
    allow_path: list[str] | None = typer.Option(None, "--allow-path", help="extra allow glob"),
    no_baseline: bool = typer.Option(False, "--no-baseline", help="ignore .envsentry-allow"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress report; keep exit code"),
) -> None:
    """Scan staged changes (default) for secrets. The pre-commit / local check path."""
    threshold = _fail_on(fail_on)
    baseline_path = _default_baseline_path()
    cfg = _config(entropy_b64, entropy_hex, allow_path, no_baseline, baseline_path)
    try:
        if staged:
            report = scanner.scan_staged(cfg)
        else:
            typer.secho("error: --no-staged requires the 'audit' command", fg="red", err=True)
            raise typer.Exit(2)
    except GitError as e:
        typer.secho(f"error: {e}", fg="red", err=True)
        raise typer.Exit(2) from e
    _emit(report, format, show, quiet, threshold)


@app.command()
def audit(
    paths: list[str] = typer.Argument(..., help="files or directories to scan"),
    fail_on: str = typer.Option("verified", "--fail-on", help="verified | possible | any"),
    format: str = typer.Option("text", "--format", "-f", help="text | json"),
    show: bool = typer.Option(False, "--show", help="reveal full tokens (default: redacted)"),
    entropy_b64: float = typer.Option(4.5, "--entropy-b64", help="base64 entropy threshold"),
    entropy_hex: float = typer.Option(3.0, "--entropy-hex", help="hex entropy threshold"),
    allow_path: list[str] | None = typer.Option(None, "--allow-path", help="extra allow glob"),
    no_baseline: bool = typer.Option(False, "--no-baseline", help="ignore .envsentry-allow"),
    quiet: bool = typer.Option(False, "--quiet", help="suppress report; keep exit code"),
) -> None:
    """Scan arbitrary files/dirs (CI full-tree or ad-hoc review)."""
    threshold = _fail_on(fail_on)
    baseline_path = _default_baseline_path()
    cfg = _config(entropy_b64, entropy_hex, allow_path, no_baseline, baseline_path)
    try:
        report = scanner.scan_paths(paths, cfg)
    except GitError as e:
        typer.secho(f"error: {e}", fg="red", err=True)
        raise typer.Exit(2) from e
    _emit(report, format, show, quiet, threshold)


@app.command(name="install-hook")
def install_hook(
    force: bool = typer.Option(False, "--force", help="back up and overwrite a foreign hook"),
) -> None:
    """Write .git/hooks/pre-commit (idempotent; refuses a foreign hook without --force)."""
    try:
        msg = git.install_hook(force=force)
    except GitError as e:
        typer.secho(f"error: {e}", fg="red", err=True)
        raise typer.Exit(2) from e
    typer.echo(msg)


@app.command(name="uninstall-hook")
def uninstall_hook() -> None:
    """Remove the envsentry pre-commit hook (restores a backup if present)."""
    try:
        msg = git.uninstall_hook()
    except GitError as e:
        typer.secho(f"error: {e}", fg="red", err=True)
        raise typer.Exit(2) from e
    typer.echo(msg)


@app.command()
def baseline(
    staged: bool = typer.Option(True, "--staged/--no-staged", help="baseline the staged diff"),
    path: list[str] | None = typer.Option(None, "--path", help="baseline these files/dirs"),
    dry_run: bool = typer.Option(False, "--dry-run", help="show what would be accepted"),
) -> None:
    """Accept currently-active findings into .envsentry-allow (fingerprints only)."""
    baseline_path = _default_baseline_path()
    cfg = ScanConfig(use_baseline=False, baseline_path=baseline_path)
    try:
        if path:
            report = scanner.scan_paths(path, cfg)
        elif staged:
            report = scanner.scan_staged(cfg)
        else:
            typer.secho("error: nothing selected to baseline", fg="red", err=True)
            raise typer.Exit(2)
    except GitError as e:
        typer.secho(f"error: {e}", fg="red", err=True)
        raise typer.Exit(2) from e

    active = report.active
    if dry_run:
        typer.echo(f"would accept {len(active)} finding(s):")
        for f in active:
            typer.echo(f"  {f.fingerprint}  {f.detector_id}  {f.path}:{f.line}")
        raise typer.Exit(0)

    added = accept(active, baseline_path)
    typer.echo(f"accepted {len(added)} new finding(s) into {Path(baseline_path).name}")


if __name__ == "__main__":
    app()
