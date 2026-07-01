"""Context-aware suppressors — envsentry's headline false-positive-reduction layer.

Each suppressor is a pure function of a single ``Finding`` (the baseline suppressor
is built separately as a closure over the loaded fingerprint set). They run *after*
detection and *before* reporting; the first that matches sets ``suppressed`` and
records its id in ``suppressed_by``.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch

from ..models import Finding, Suppressor

# --- 1. placeholder lexicon ------------------------------------------------
# Deliberately does NOT treat a bare "example" substring as a placeholder: the
# canonical AWS docs key (AKIAIOSFODNN7EXAMPLE) is a real-format token and must
# stay VERIFIED. "EXAMPLE_"-style suppression is the varname-example rule's job.
_TOKEN_PLACEHOLDER = re.compile(
    r"""
      x{4,}                     # xxxx...
    | 0{4,}                     # 0000...
    | (?:0123456789|1234567890) # obvious digit ramps
    | (.)\1{5,}                 # any char repeated 6+ times
    | deadbeef
    | foobar
    | changeme
    | placeholder
    | redacted
    | dummy
    """,
    re.IGNORECASE | re.VERBOSE,
)
_LINE_PLACEHOLDER = re.compile(
    r"""
      <[^>]{2,}>                # <your-key> angle-bracket template
    | your[-_ ]?(?:key|token|secret|api[-_ ]?key)
    | insert.{0,20}here
    | changeme
    | replace[-_ ]?me
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _placeholder_applies(f: Finding) -> bool:
    tok = f.secret.token
    if _TOKEN_PLACEHOLDER.search(tok):
        return True
    return bool(_LINE_PLACEHOLDER.search(f.line_text))


# --- 2. varname-example ----------------------------------------------------
# The assignment target contains EXAMPLE/SAMPLE/FAKE/DUMMY/MOCK/TEST.
_VARNAME_EXAMPLE = re.compile(
    r"^\s*(?:export\s+)?[A-Za-z0-9_]*?(EXAMPLE|SAMPLE|FAKE|DUMMY|MOCK|TEST)[A-Za-z0-9_]*\s*[:=]",
    re.IGNORECASE,
)


def _varname_applies(f: Finding) -> bool:
    return bool(_VARNAME_EXAMPLE.search(f.line_text))


# --- 3. path-allowlist -----------------------------------------------------
_ALLOW_GLOBS: tuple[str, ...] = (
    "*/test/*",
    "*/tests/*",
    "*/__tests__/*",
    "*/fixtures/*",
    "*/testdata/*",
    "*/examples/*",
    "*/mocks/*",
    "*.example",
    "*.sample",
    "*.md",
    "*.rst",
    ".env.example",
    ".env.sample",
    "*/.env.example",
    "*/.env.sample",
)


def _path_matches(path: str, globs: tuple[str, ...]) -> bool:
    norm = path.replace("\\", "/")
    base = norm.rsplit("/", 1)[-1]
    for g in globs:
        if fnmatch(norm, g) or fnmatch(base, g):
            return True
        # allow bare-dir globs to match a leading path too
        if fnmatch("/" + norm, g):
            return True
    return False


def build_path_suppressor(extra_globs: tuple[str, ...] = ()) -> Suppressor:
    globs = _ALLOW_GLOBS + tuple(extra_globs)
    return Suppressor(
        id="path-allowlist",
        reason="file path is a test/fixture/example/doc location",
        applies=lambda f: _path_matches(f.path, globs),
    )


# --- 4. structural ---------------------------------------------------------
_GIT_SHA = re.compile(r"\A[0-9a-f]{7,40}\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_UUID = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_ISO_TS = re.compile(r"\A\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_INT_SEQ = re.compile(r"\A\d{7,}\Z")


def _structural_applies(f: Finding) -> bool:
    tok = f.secret.token
    return bool(
        _GIT_SHA.match(tok)
        or _SHA256.match(tok)
        or _UUID.match(tok)
        or _ISO_TS.match(tok)
        or _INT_SEQ.match(tok)
    )


# --- assembled default suppressors (1-4; baseline is added by context.__init__) ---
def default_suppressors(extra_allow_globs: tuple[str, ...] = ()) -> list[Suppressor]:
    return [
        Suppressor("placeholder", "token/line is a known placeholder", _placeholder_applies),
        Suppressor(
            "varname-example", "assignment target marked example/sample/fake", _varname_applies
        ),
        build_path_suppressor(extra_allow_globs),
        Suppressor(
            "structural", "token is a git SHA / UUID / hash / timestamp", _structural_applies
        ),
    ]


# Module-level instances for direct unit testing.
PLACEHOLDER = Suppressor("placeholder", "token/line is a known placeholder", _placeholder_applies)
VARNAME_EXAMPLE = Suppressor(
    "varname-example", "assignment target marked example/sample/fake", _varname_applies
)
PATH_ALLOWLIST = build_path_suppressor()
STRUCTURAL = Suppressor(
    "structural", "token is a git SHA / UUID / hash / timestamp", _structural_applies
)
SUPPRESSORS: list[Suppressor] = [PLACEHOLDER, VARNAME_EXAMPLE, PATH_ALLOWLIST, STRUCTURAL]
