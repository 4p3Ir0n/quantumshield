"""Tests for quantumshield.sarif — SARIF 2.1.0 output."""

import json
import os
import subprocess
import sys

from quantumshield.sarif import build_sarif, write_sarif
from quantumshield.scanner import Finding, Occurrence, Scanner

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def mk(algorithm, severity, occurrences, asset_type="algorithm", nist_qsl=0):
    return Finding(algorithm=algorithm, asset_type=asset_type, severity=severity,
                   nist_qsl=nist_qsl, primitive="hash", note=f"{algorithm} note",
                   occurrences=[Occurrence(*o) for o in occurrences])


def rules_of(doc):
    return doc["runs"][0]["tool"]["driver"]["rules"]


def results_of(doc):
    return doc["runs"][0]["results"]


# ------------------------------------------------------------------ shape
def test_envelope_is_sarif_210():
    doc = build_sarif([mk("MD5", "HIGH", [("a.py", 3, "md5(x)", "MD5 hashing")])])
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert doc["runs"][0]["tool"]["driver"]["name"] == "QuantumShield"


def test_result_carries_location_and_fingerprint():
    doc = build_sarif([mk("MD5", "HIGH", [("a.py", 3, "md5(x)", "MD5 hashing")])])
    r = results_of(doc)[0]
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "a.py"
    assert loc["region"]["startLine"] == 3
    assert r["partialFingerprints"]["quantumshieldFingerprint/v1"]


def test_windows_paths_become_posix_uris():
    doc = build_sarif([mk("MD5", "HIGH", [("src\\deep\\a.py", 1, "md5(x)", "h")])])
    uri = results_of(doc)[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/deep/a.py"


# --------------------------------------------------------------- severity
def test_severity_maps_to_level_and_security_severity():
    doc = build_sarif([
        mk("RSA", "CRITICAL", [("a.py", 1, "rsa", "h")]),
        mk("MD5", "HIGH", [("b.py", 1, "md5", "h")]),
        mk("AES-128", "MEDIUM", [("c.py", 1, "aes", "h")]),
        mk("SHA-256", "LOW", [("d.py", 1, "sha", "h")]),
    ])
    levels = {r["ruleId"]: r["level"] for r in results_of(doc)}
    assert levels["quantumshield/rsa"] == "error"
    assert levels["quantumshield/md5"] == "error"
    assert levels["quantumshield/aes-128"] == "warning"
    assert levels["quantumshield/sha-256"] == "note"

    sev = {r["id"]: r["properties"]["security-severity"] for r in rules_of(doc)}
    assert sev["quantumshield/rsa"] == "9.0"
    assert sev["quantumshield/sha-256"] == "3.0"


def test_safe_findings_are_not_emitted_as_alerts():
    """SAFE findings are positive detections (PQC adoption). Turning them into
    code-scanning alerts would file bugs against correct code."""
    doc = build_sarif([
        mk("ML-KEM", "SAFE", [("pqc.py", 1, "mlkem", "h")], nist_qsl=3),
        mk("AES-256", "SAFE", [("a.py", 1, "aes256", "h")], nist_qsl=5),
        mk("MD5", "HIGH", [("b.py", 1, "md5", "h")]),
    ])
    assert [r["ruleId"] for r in results_of(doc)] == ["quantumshield/md5"]
    assert [r["id"] for r in rules_of(doc)] == ["quantumshield/md5"]


def test_no_findings_yields_empty_but_valid_run():
    doc = build_sarif([])
    assert results_of(doc) == [] and rules_of(doc) == []
    assert doc["version"] == "2.1.0"


# ------------------------------------------------------------------ rules
def test_rule_is_defined_once_but_result_per_occurrence():
    doc = build_sarif([mk("MD5", "HIGH", [
        ("a.py", 1, "md5(x)", "h"), ("b.py", 9, "md5(y)", "h"), ("c.py", 4, "md5(z)", "h")])])
    assert len(rules_of(doc)) == 1
    assert len(results_of(doc)) == 3


def test_rule_index_points_at_the_right_rule():
    doc = build_sarif([
        mk("RSA", "CRITICAL", [("a.py", 1, "rsa", "h")]),
        mk("MD5", "HIGH", [("b.py", 1, "md5", "h")]),
    ])
    rules = rules_of(doc)
    for r in results_of(doc):
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]


def test_rule_id_slug_is_clean_for_awkward_names():
    doc = build_sarif([mk("X.509 certificate (RSA-2048)", "CRITICAL",
                          [("s.pem", 1, "cert", "h")], asset_type="certificate")])
    assert rules_of(doc)[0]["id"] == "quantumshield/x-509-certificate-rsa-2048"


def test_probe_style_finding_uses_logical_location():
    # `probe` findings describe an endpoint, not a file (line 0).
    doc = build_sarif([mk("TLSv1.1", "HIGH", [("host.example:443", 0, "", "legacy TLS")],
                          asset_type="protocol")])
    loc = results_of(doc)[0]["locations"][0]
    assert "physicalLocation" not in loc
    assert loc["logicalLocations"][0]["name"] == "host.example:443"


# -------------------------------------------------------------------- I/O
def test_write_sarif_roundtrip(tmp_path):
    out = tmp_path / "results.sarif"
    write_sarif([mk("MD5", "HIGH", [("a.py", 1, "md5", "h")])], str(out), "proj")
    doc = json.loads(out.read_text())
    assert doc["runs"][0]["automationDetails"]["id"] == "quantumshield/proj"


def test_sarif_from_a_real_scan(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    doc = build_sarif(Scanner(str(tmp_path)).scan())
    assert results_of(doc)[0]["ruleId"] == "quantumshield/md5"


# -------------------------------------------------------------------- CLI
def test_cli_sarif_flag_writes_file(tmp_path):
    (tmp_path / "bad.py").write_text("k = rsa.generate_private_key(65537)\n")
    out = tmp_path / "out"
    r = subprocess.run(
        [sys.executable, "-m", "quantumshield", "scan", str(tmp_path),
         "-o", str(out), "--json-only", "--sarif"],
        capture_output=True, text=True, cwd=REPO_ROOT)
    assert r.returncode == 1
    doc = json.loads((out / "results.sarif").read_text())
    assert doc["version"] == "2.1.0"
    assert any(x["ruleId"] == "quantumshield/rsa" for x in results_of(doc))
