"""Tests for the CI-gating surface: --fail-on and the baseline flags."""

import json
import os
import subprocess
import sys

import pytest

from quantumshield.cli import _should_fail

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CRITICAL_SRC = "k = rsa.generate_private_key(65537)\n"          # CRITICAL
HIGH_ONLY_SRC = "import hashlib\nh = hashlib.md5(b'x')\n"       # HIGH, no CRITICAL


def run_scan(tmp_path, *extra):
    return subprocess.run(
        [sys.executable, "-m", "quantumshield", "scan", str(tmp_path),
         "-o", str(tmp_path / "out"), "--json-only", *extra],
        capture_output=True, text=True, cwd=REPO_ROOT)


# ------------------------------------------------------------- unit: gating
@pytest.mark.parametrize("counts,fail_on,expected", [
    ({"CRITICAL": 1, "HIGH": 0}, "critical", True),
    ({"CRITICAL": 0, "HIGH": 3}, "critical", False),
    ({"CRITICAL": 0, "HIGH": 3}, "high", True),
    ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1}, "high", False),
    ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1}, "medium", True),
    ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 2}, "low", True),
    ({"CRITICAL": 5, "HIGH": 5}, "never", False),
    ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1}, "any", True),
    ({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 9}, "any", False),
])
def test_should_fail(counts, fail_on, expected):
    assert _should_fail(counts, fail_on) is expected


def test_safe_findings_never_trip_the_gate():
    assert _should_fail({"SAFE": 10}, "critical") is False
    assert _should_fail({"SAFE": 10}, "any") is False


# --------------------------------------------------------------- CLI: gate
def test_default_gate_fails_on_critical(tmp_path):
    (tmp_path / "a.py").write_text(CRITICAL_SRC)
    assert run_scan(tmp_path).returncode == 1


def test_default_gate_passes_when_only_high(tmp_path):
    (tmp_path / "a.py").write_text(HIGH_ONLY_SRC)
    assert run_scan(tmp_path).returncode == 0


def test_fail_on_high_catches_high(tmp_path):
    (tmp_path / "a.py").write_text(HIGH_ONLY_SRC)
    assert run_scan(tmp_path, "--fail-on", "high").returncode == 1


def test_fail_on_never_always_passes(tmp_path):
    (tmp_path / "a.py").write_text(CRITICAL_SRC)
    assert run_scan(tmp_path, "--fail-on", "never").returncode == 0


# ----------------------------------------------------------- CLI: baseline
def test_write_baseline_exits_zero_and_writes_file(tmp_path):
    (tmp_path / "a.py").write_text(CRITICAL_SRC)
    bl = tmp_path / "baseline.json"
    r = run_scan(tmp_path, "--write-baseline", str(bl))
    assert r.returncode == 0                       # bookkeeping run never gates
    assert json.loads(bl.read_text())["fingerprints"]


def test_baseline_lets_a_team_adopt_the_gate_on_existing_debt(tmp_path):
    (tmp_path / "a.py").write_text(CRITICAL_SRC)
    bl = tmp_path / "baseline.json"
    run_scan(tmp_path, "--write-baseline", str(bl))
    # Same critical finding, now baselined -> gate passes.
    assert run_scan(tmp_path, "--baseline", str(bl)).returncode == 0


def test_baseline_still_fails_on_newly_added_crypto(tmp_path):
    (tmp_path / "a.py").write_text(CRITICAL_SRC)
    bl = tmp_path / "baseline.json"
    run_scan(tmp_path, "--write-baseline", str(bl))

    (tmp_path / "b.py").write_text("e = ec.generate_private_key(ec.SECP256R1())\n")
    r = run_scan(tmp_path, "--baseline", str(bl))
    assert r.returncode == 1
    assert "new findings only" in r.stdout


def test_missing_baseline_file_is_an_error(tmp_path):
    (tmp_path / "a.py").write_text(CRITICAL_SRC)
    r = run_scan(tmp_path, "--baseline", str(tmp_path / "nope.json"))
    assert r.returncode == 2
    assert "could not read baseline" in r.stderr
