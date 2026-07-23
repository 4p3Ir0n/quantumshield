"""QuantumShield — SARIF 2.1.0 output.

SARIF is what lets findings land where security teams already work: GitHub
code scanning, Azure DevOps, and most SAST dashboards ingest it natively. A
tool whose output has to be read as a bespoke HTML report competes with the
dashboard; a tool that emits SARIF joins it.

Two deliberate choices:

* **SAFE findings are not emitted as results.** They are *positive* detections
  (AES-256, SHA-384, ML-KEM adoption) — turning them into code-scanning alerts
  would file bugs against correct code. They stay in the CBOM and the HTML
  report, where "you already use PQC here" is useful information.
* **One result per occurrence**, not per algorithm, so each alert anchors to a
  real file and line the way a code-scanning UI expects.
"""

from __future__ import annotations

import json

from . import __version__
from .suppress import fingerprint

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/schemas/sarif-schema-2.1.0.json"
INFO_URI = "https://github.com/4p3Ir0n/quantumshield"

# SARIF `level` is only error/warning/note/none, so the five-band severity
# model is compressed. `security-severity` (a 0-10 string GitHub reads to
# bucket alerts as critical/high/medium/low) preserves the distinction.
LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
SECURITY_SEVERITY = {"CRITICAL": "9.0", "HIGH": "7.0", "MEDIUM": "5.0", "LOW": "3.0"}

REPORTED_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _rule_id(algorithm: str) -> str:
    slug = "".join(ch if ch.isalnum() else "-" for ch in algorithm).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return f"quantumshield/{slug.lower()}"


def _uri(path: str) -> str:
    """SARIF artifact URIs are POSIX-style relative paths."""
    return path.replace("\\", "/")


def build_sarif(findings, target: str = "") -> dict:
    reported = [f for f in findings if f.severity in REPORTED_SEVERITIES]

    rules, rule_index = [], {}
    for f in reported:
        rid = _rule_id(f.algorithm)
        if rid in rule_index:
            continue
        rule_index[rid] = len(rules)
        tags = ["security", "cryptography", "post-quantum", f"severity/{f.severity.lower()}"]
        if f.asset_type:
            tags.append(f"asset/{f.asset_type}")
        rules.append({
            "id": rid,
            "name": f.algorithm.replace(" ", ""),
            "shortDescription": {"text": f"Quantum-vulnerable cryptography: {f.algorithm}"},
            "fullDescription": {"text": f.note},
            "help": {
                "text": f.note,
                "markdown": f"**{f.algorithm}** — {f.severity}\n\n{f.note}",
            },
            "defaultConfiguration": {"level": LEVELS.get(f.severity, "note")},
            "properties": {
                "tags": tags,
                "security-severity": SECURITY_SEVERITY.get(f.severity, "1.0"),
                "quantumshield:severity": f.severity,
                "quantumshield:nistQuantumSecurityLevel": f.nist_qsl,
            },
        })

    results = []
    for f in reported:
        rid = _rule_id(f.algorithm)
        for occ in f.occurrences:
            message = f"{f.algorithm} — {occ.hint}." if occ.hint else f"{f.algorithm} detected."
            result = {
                "ruleId": rid,
                "ruleIndex": rule_index[rid],
                "level": LEVELS.get(f.severity, "note"),
                "message": {"text": f"{message} {f.note}"},
                "partialFingerprints": {
                    "quantumshieldFingerprint/v1": fingerprint(f.algorithm, occ.path, occ.snippet)
                },
            }
            if occ.line and occ.line > 0:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(occ.path)},
                        "region": {"startLine": occ.line,
                                   "snippet": {"text": occ.snippet}},
                    }
                }]
            else:
                # `probe` findings describe a network endpoint, not a file, so
                # there is no physical location to point at.
                result["locations"] = [{
                    "logicalLocations": [{"name": occ.path, "kind": "resource"}]
                }]
            results.append(result)

    run = {
        "tool": {"driver": {
            "name": "QuantumShield",
            "version": __version__,
            "informationUri": INFO_URI,
            "rules": rules,
        }},
        "results": results,
    }
    if target:
        run["automationDetails"] = {"id": f"quantumshield/{target}"}

    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}


def write_sarif(findings, path: str, target: str = ""):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_sarif(findings, target), fh, indent=2)
