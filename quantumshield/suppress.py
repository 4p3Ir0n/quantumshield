"""QuantumShield — noise control: ignore patterns, inline suppressions, baselines.

The first scan of a real repository produces a wall of findings, most of which
a team has already accepted (vendored code, test fixtures, a legacy path with a
ticket against it). Without a way to quieten those, the tool gets uninstalled.
Three mechanisms, in increasing precision:

1. `.quantumshieldignore` at the scan root — gitignore-style path globs, for
   whole directories or file types that should never be scanned.
2. Inline `quantumshield: ignore` comments — per-line, reviewable in code
   review, and they travel with the code.
3. A baseline file — records everything found today so CI reports only what's
   *new*. This is what lets a team adopt the gate without first fixing years
   of accumulated debt.

Fingerprints deliberately exclude the line number so a finding survives
unrelated edits that shift code up or down the file.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone

IGNORE_FILENAME = ".quantumshieldignore"

# QuantumShield's own artifacts name algorithms in plain text ("algorithm":
# "MD5"), so scanning a repo that has a committed CBOM, SARIF file or baseline
# in it would re-report every algorithm those files record. Always skip them.
DEFAULT_IGNORE_PATTERNS = [
    "quantumshield-out/",
    "*.cdx.json",
    "results.sarif",
]

# `# quantumshield: ignore` / `// quantumshield: ignore[MD5] reason here`
# Comment syntax is not parsed — we just look for the marker anywhere on the
# line, which makes this work for #, //, /* */, --, ; and friends alike.
INLINE_RE = re.compile(
    r"quantumshield\s*:\s*ignore(?:\[([^\]]*)\])?(?:\s+(.*))?$",
    re.IGNORECASE)


# --------------------------------------------------------------- ignore file
def _glob_to_regex(pattern: str) -> re.Pattern:
    """Translate a gitignore-ish glob to a regex matched against a relative
    POSIX path. Supports `**`, `*`, `?`, and a trailing `/` for directories.
    Negation (`!`) is deliberately unsupported — see README."""
    pattern = pattern.strip().replace("\\", "/")
    dir_only = pattern.endswith("/")
    if dir_only:
        pattern = pattern[:-1]
    # A pattern with no slash matches at any depth (gitignore behaviour).
    anchored = "/" in pattern
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    body = "".join(out)
    prefix = "" if anchored else "(?:.*/)?"
    # Trailing `(?:/.*)?` lets a pattern match a directory *and* everything
    # under it, so `vendor/` and `vendor` both cover the whole subtree.
    return re.compile(f"^{prefix}{body}(?:/.*)?$")


class IgnoreRules:
    """Path-glob ignores loaded from a `.quantumshieldignore` file."""

    def __init__(self, patterns: list[str] | None = None):
        self.patterns: list[str] = []
        self._regexes: list[re.Pattern] = []
        for p in patterns or []:
            self.add(p)

    def add(self, pattern: str):
        pattern = pattern.strip()
        if not pattern or pattern.startswith("#"):
            return
        self.patterns.append(pattern)
        self._regexes.append(_glob_to_regex(pattern))

    def matches(self, rel_path: str) -> bool:
        rel = rel_path.replace("\\", "/")
        if rel.startswith("./"):      # not lstrip("./") — that would eat the
            rel = rel[2:]            # leading dot of paths like `.github/...`
        return any(rx.match(rel) for rx in self._regexes)

    def __bool__(self):
        return bool(self._regexes)

    @classmethod
    def load(cls, root: str, defaults: bool = True) -> "IgnoreRules":
        """Load `.quantumshieldignore` from `root`, seeded with the built-in
        self-artifact patterns. Pass `defaults=False` for a literal file read."""
        rules = cls(DEFAULT_IGNORE_PATTERNS if defaults else None)
        try:
            with open(os.path.join(root, IGNORE_FILENAME), "r",
                      encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    rules.add(line)
        except OSError:
            pass  # no ignore file is the common case
        return rules


def self_artifact_patterns(root: str, *paths: str | None) -> list[str]:
    """Ignore patterns for QuantumShield's own output/baseline files when they
    live inside the tree being scanned. The CLI knows these paths exactly, so
    they can be excluded precisely rather than guessed at by name."""
    out = []
    root_abs = os.path.abspath(root)
    for p in paths:
        if not p:
            continue
        rel = os.path.relpath(os.path.abspath(p), root_abs)
        if rel.startswith("..") or os.path.isabs(rel):
            continue  # outside the scanned tree; nothing to exclude
        out.append(rel.replace("\\", "/"))
    return out


# --------------------------------------------------------- inline suppression
def inline_suppression(line: str) -> tuple[bool, set[str], str] | None:
    """Parse an inline suppression marker.

    Returns (suppress_all, {ALGOS}, reason) or None if the line has no marker.
    `ignore` with no bracket suppresses every finding on the line;
    `ignore[MD5,SHA-1]` suppresses only those algorithms.
    """
    m = INLINE_RE.search(line)
    if not m:
        return None
    algos_raw, reason = m.group(1), (m.group(2) or "").strip()
    if algos_raw is None:
        return True, set(), reason
    algos = {a.strip().upper() for a in algos_raw.split(",") if a.strip()}
    return (not algos), algos, reason


def is_suppressed(line: str, algorithm: str) -> bool:
    parsed = inline_suppression(line)
    if parsed is None:
        return False
    suppress_all, algos, _ = parsed
    return suppress_all or algorithm.upper() in algos


# ----------------------------------------------------------------- baselines
def fingerprint(algorithm: str, path: str, snippet: str) -> str:
    """Stable identity for one occurrence.

    Line numbers are excluded on purpose: an occurrence that moves because
    something was inserted above it is the *same* finding, and a baseline that
    forgot that would re-report the whole file on every refactor.
    """
    norm_path = path.replace("\\", "/")
    norm_snippet = " ".join(snippet.split())
    blob = f"{algorithm}\x00{norm_path}\x00{norm_snippet}".encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def build_baseline(findings, tool_version: str = "") -> dict:
    entries = {}
    for f in findings:
        for occ in f.occurrences:
            fp = fingerprint(f.algorithm, occ.path, occ.snippet)
            entries[fp] = {"algorithm": f.algorithm,
                           "path": occ.path.replace("\\", "/"),
                           "severity": f.severity}
    return {
        "version": 1,
        "tool": "quantumshield",
        "toolVersion": tool_version,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "fingerprints": entries,
    }


def write_baseline(findings, path: str, tool_version: str = "") -> int:
    data = build_baseline(findings, tool_version)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    return len(data["fingerprints"])


def load_baseline(path: str) -> set[str]:
    """Return the set of baselined fingerprints. Raises OSError/ValueError if
    the file is missing or malformed — callers should surface that rather than
    silently scanning with no baseline."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "fingerprints" not in data:
        raise ValueError(f"{path} is not a QuantumShield baseline file")
    return set(data["fingerprints"])


def apply_baseline(findings, baselined: set[str]) -> tuple[list, int]:
    """Drop occurrences already present in the baseline, and drop findings left
    with none. Returns (remaining_findings, suppressed_occurrence_count)."""
    remaining, suppressed = [], 0
    for f in findings:
        keep = []
        for occ in f.occurrences:
            if fingerprint(f.algorithm, occ.path, occ.snippet) in baselined:
                suppressed += 1
            else:
                keep.append(occ)
        if keep:
            f.occurrences = keep
            remaining.append(f)
        # a finding whose occurrences were all baselined drops out entirely;
        # those occurrences are already counted in `suppressed` above
    return remaining, suppressed
