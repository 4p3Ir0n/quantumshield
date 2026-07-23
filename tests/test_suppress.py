"""Tests for quantumshield.suppress — ignore rules, inline suppression, baselines."""

import json

import pytest

from quantumshield.scanner import Scanner
from quantumshield.suppress import (
    IgnoreRules, apply_baseline, fingerprint, inline_suppression, is_suppressed,
    load_baseline, write_baseline,
)


def algos(findings):
    return {f.algorithm for f in findings}


# ------------------------------------------------------------- ignore globs
@pytest.mark.parametrize("pattern,path,expected", [
    ("thirdparty/", "thirdparty/lib.py", True),
    ("thirdparty/", "thirdparty/deep/nested/lib.py", True),
    ("thirdparty/", "src/thirdparty/lib.py", True),      # unanchored: any depth
    ("thirdparty/", "src/thirdpartyish.py", False),
    ("*.min.js", "src/app.min.js", True),
    ("*.min.js", "src/app.js", False),
    ("**/generated/**", "a/generated/b.py", True),
    ("src/*.py", "src/a.py", True),
    ("src/*.py", "src/deep/a.py", False),                # `*` stops at a slash
    ("src/vendor", "src/vendor/x.py", True),
    ("build", "build/out.js", True),
])
def test_ignore_glob_matching(pattern, path, expected):
    assert IgnoreRules([pattern]).matches(path) is expected


def test_ignore_handles_windows_separators():
    assert IgnoreRules(["thirdparty/"]).matches("thirdparty\\lib.py") is True


def test_ignore_does_not_mangle_dotfile_paths():
    # A naive lstrip("./") would turn ".github/x.yml" into "github/x.yml".
    assert IgnoreRules([".github/"]).matches(".github/workflows/ci.yml") is True
    assert IgnoreRules(["thirdparty/"]).matches(".github/workflows/ci.yml") is False


def test_ignore_file_skips_comments_and_blanks(tmp_path):
    (tmp_path / ".quantumshieldignore").write_text("# a comment\n\nthirdparty/\n\n")
    rules = IgnoreRules.load(str(tmp_path), defaults=False)
    assert rules.patterns == ["thirdparty/"]
    assert rules.matches("thirdparty/x.py")


def test_missing_ignore_file_is_not_an_error(tmp_path):
    assert not IgnoreRules.load(str(tmp_path), defaults=False)


def test_load_seeds_self_artifact_defaults(tmp_path):
    rules = IgnoreRules.load(str(tmp_path))
    assert rules.matches("cbom.cdx.json")
    assert rules.matches("quantumshield-out/report.html")


# ------------------------------------------------------- inline suppression
@pytest.mark.parametrize("line,algo,expected", [
    ("h = md5(x)  # quantumshield: ignore", "MD5", True),
    ("h = md5(x)  # quantumshield: ignore[MD5]", "MD5", True),
    ("h = md5(x)  // quantumshield: ignore[MD5,SHA-1]", "SHA-1", True),
    ("h = md5(x)  # quantumshield: ignore[SHA-1]", "MD5", False),
    ("h = md5(x)  # QuantumShield: Ignore[md5]", "MD5", True),   # case-insensitive
    ("h = md5(x)", "MD5", False),
    ("h = md5(x)  # todo: remove md5", "MD5", False),
])
def test_inline_suppression(line, algo, expected):
    assert is_suppressed(line, algo) is expected


def test_inline_suppression_captures_reason():
    suppress_all, algos_set, reason = inline_suppression(
        "x  # quantumshield: ignore[MD5] legacy vendor feed, JIRA-123")
    assert suppress_all is False
    assert algos_set == {"MD5"}
    assert reason == "legacy vendor feed, JIRA-123"


def test_inline_suppression_absent_returns_none():
    assert inline_suppression("just some code") is None


# ------------------------------------------------------------- fingerprints
def test_fingerprint_is_line_number_independent():
    # Same code, different position in the file -> same fingerprint, so a
    # baseline survives unrelated edits above the finding.
    assert fingerprint("MD5", "src/a.py", "h = md5(x)") == \
           fingerprint("MD5", "src/a.py", "h = md5(x)")


def test_fingerprint_normalises_path_and_whitespace():
    assert fingerprint("MD5", "src\\a.py", "h  =  md5(x)") == \
           fingerprint("MD5", "src/a.py", "h = md5(x)")


def test_fingerprint_differs_on_algorithm_path_and_code():
    base = fingerprint("MD5", "src/a.py", "h = md5(x)")
    assert base != fingerprint("SHA-1", "src/a.py", "h = md5(x)")
    assert base != fingerprint("MD5", "src/b.py", "h = md5(x)")
    assert base != fingerprint("MD5", "src/a.py", "h = md5(y)")


# ---------------------------------------------------------------- baselines
def _scan(tmp_path, src, name="a.py"):
    """Scan a source tree. The baseline file is kept in a sibling directory so
    the scan never sees it — see test_baseline_file_inside_repo_is_not_scanned
    for the case where it *is* inside the tree."""
    src_dir = tmp_path / "proj"
    src_dir.mkdir(exist_ok=True)
    (src_dir / name).write_text(src)
    return Scanner(str(src_dir)).scan()


def test_baseline_roundtrip(tmp_path):
    findings = _scan(tmp_path, "import hashlib\nh = hashlib.md5(b'x')\n")
    bl = tmp_path / "baseline.json"
    n = write_baseline(findings, str(bl), "0.4.0")
    assert n == 1
    data = json.loads(bl.read_text())
    assert data["version"] == 1 and data["toolVersion"] == "0.4.0"
    assert len(load_baseline(str(bl))) == 1


def test_baseline_suppresses_known_findings(tmp_path):
    findings = _scan(tmp_path, "import hashlib\nh = hashlib.md5(b'x')\n")
    bl = tmp_path / "baseline.json"
    write_baseline(findings, str(bl))

    again = _scan(tmp_path, "import hashlib\nh = hashlib.md5(b'x')\n")
    remaining, suppressed = apply_baseline(again, load_baseline(str(bl)))
    assert remaining == [] and suppressed == 1


def test_baseline_still_reports_new_findings(tmp_path):
    findings = _scan(tmp_path, "import hashlib\nh = hashlib.md5(b'x')\n")
    bl = tmp_path / "baseline.json"
    write_baseline(findings, str(bl))

    grown = _scan(tmp_path, "import hashlib\nh = hashlib.md5(b'x')\n"
                            "s = hashlib.sha1(b'y')\n")
    remaining, suppressed = apply_baseline(grown, load_baseline(str(bl)))
    assert algos(remaining) == {"SHA-1"}
    assert suppressed == 1


def test_baseline_survives_code_moving_down_a_file(tmp_path):
    findings = _scan(tmp_path, "import hashlib\nh = hashlib.md5(b'x')\n")
    bl = tmp_path / "baseline.json"
    write_baseline(findings, str(bl))

    # Same finding, pushed down by unrelated lines above it.
    moved = _scan(tmp_path, "import hashlib\n# note\n# note\n# note\n"
                            "h = hashlib.md5(b'x')\n")
    remaining, _ = apply_baseline(moved, load_baseline(str(bl)))
    assert remaining == []


def test_baseline_file_inside_repo_is_not_scanned(tmp_path):
    """Regression: a committed baseline/CBOM names algorithms in plain text
    ("algorithm": "MD5"), so scanning a repo containing one used to re-report
    every algorithm it recorded."""
    (tmp_path / "a.py").write_text("x = 1\n")
    findings = _scan(tmp_path, "import hashlib\nh = hashlib.md5(b'x')\n")
    write_baseline(findings, str(tmp_path / "proj" / "qs-baseline.json"))
    (tmp_path / "proj" / "cbom.cdx.json").write_text(
        '{"components":[{"name":"RSA"},{"name":"SHA-1"}]}')

    scanner = Scanner(str(tmp_path / "proj"))
    scanner.ignore.add("qs-baseline.json")      # as the CLI does for --baseline
    assert algos(scanner.scan()) == {"MD5"}     # not RSA/SHA-1 from the artifacts


def test_default_ignores_cover_cbom_and_sarif(tmp_path):
    (tmp_path / "cbom.cdx.json").write_text('{"components":[{"name":"RSA"}]}')
    (tmp_path / "results.sarif").write_text('{"runs":[{"results":[{"x":"MD5"}]}]}')
    assert algos(Scanner(str(tmp_path)).scan()) == set()


def test_malformed_baseline_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "a baseline"}')
    with pytest.raises(ValueError):
        load_baseline(str(bad))


# ------------------------------------------------------- scanner integration
def test_scanner_honours_ignore_file(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    (tmp_path / "thirdparty").mkdir()
    (tmp_path / "thirdparty" / "lib.py").write_text("import hashlib\ns = hashlib.sha1(b'x')\n")
    (tmp_path / ".quantumshieldignore").write_text("thirdparty/\n")

    scanner = Scanner(str(tmp_path))
    found = algos(scanner.scan())
    assert found == {"MD5"}                 # SHA-1 in thirdparty/ never scanned
    assert scanner.dirs_ignored == 1


def test_scanner_without_ignore_file_sees_everything(tmp_path):
    # Control for the test above: same tree, no ignore file.
    (tmp_path / "thirdparty").mkdir()
    (tmp_path / "thirdparty" / "lib.py").write_text("import hashlib\ns = hashlib.sha1(b'x')\n")
    assert algos(Scanner(str(tmp_path)).scan()) == {"SHA-1"}


def test_scanner_honours_inline_suppression(tmp_path):
    src = ("import hashlib\n"
           "h = hashlib.md5(b'x')\n"
           "s = hashlib.sha1(b'y')  # quantumshield: ignore[SHA-1] tracked in JIRA-123\n")
    scanner = Scanner(str(tmp_path))
    (tmp_path / "a.py").write_text(src)
    found = algos(scanner.scan())
    assert found == {"MD5"}
    assert scanner.suppressed_inline == 1


def test_inline_suppression_works_for_regex_path_too(tmp_path):
    # nginx.conf is matched by regex, not AST — suppression must apply there.
    (tmp_path / "nginx.conf").write_text(
        "ssl_protocols TLSv1.1 TLSv1.2;  # quantumshield: ignore\n")
    assert algos(Scanner(str(tmp_path)).scan()) == set()


def test_explicit_ignore_rules_override_file(tmp_path):
    (tmp_path / ".quantumshieldignore").write_text("*.py\n")
    (tmp_path / "a.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    # Passing IgnoreRules() explicitly means "no ignores", overriding the file.
    assert algos(Scanner(str(tmp_path), ignore=IgnoreRules()).scan()) == {"MD5"}
