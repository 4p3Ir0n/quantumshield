"""QuantumShield — CycloneDX 1.6 CBOM generation and quantum risk scoring."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from . import __version__
from .scanner import Finding

PRIMITIVE_MAP = {
    "pke": "pke", "signature": "signature", "key-agree": "key-agree",
    "kem": "kem", "hash": "hash", "block-cipher": "block-cipher",
    "stream-cipher": "stream-cipher",
}


def build_cbom(findings: list[Finding], target: str, score: dict) -> dict:
    """Render findings as a CycloneDX 1.6 cryptographic bill of materials."""
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    components = []
    for f in findings:
        ref = f"crypto/{f.asset_type}/{f.algorithm.replace(' ', '-')}-{uuid.uuid4().hex[:8]}"
        comp = {
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": f.algorithm,
            "cryptoProperties": {"assetType": f.asset_type},
            "evidence": {
                "occurrences": [
                    {"location": o.path, "line": o.line, "additionalContext": o.hint}
                    for o in f.occurrences[:50]
                ]
            },
            "properties": [
                {"name": "quantumshield:severity", "value": f.severity},
                {"name": "quantumshield:recommendation", "value": f.note},
            ],
        }
        if f.oid:
            comp["cryptoProperties"]["oid"] = f.oid
        if f.asset_type == "algorithm":
            comp["cryptoProperties"]["algorithmProperties"] = {
                "primitive": PRIMITIVE_MAP.get(f.primitive, "other"),
                "executionEnvironment": "software-plain-ram",
                "nistQuantumSecurityLevel": f.nist_qsl,
            }
        elif f.asset_type == "certificate" and f.detail:
            comp["cryptoProperties"]["certificateProperties"] = {
                "subjectName": f.detail.split(" | ")[0],
            }
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": {"components": [{
                "type": "application", "name": "QuantumShield",
                "version": __version__,
            }]},
            "component": {"type": "application", "name": target,
                          "bom-ref": f"target/{uuid.uuid4().hex[:8]}"},
            "properties": [
                {"name": "quantumshield:readiness-score", "value": str(score["score"])},
                {"name": "quantumshield:grade", "value": score["grade"]},
            ],
        },
        "components": components,
    }


# ---------------------------------------------------------------- scoring
WEIGHTS = {"CRITICAL": 14, "HIGH": 8, "MEDIUM": 4, "LOW": 1, "SAFE": 0}
OCCURRENCE_BONUS = {"CRITICAL": 0.6, "HIGH": 0.35, "MEDIUM": 0.15, "LOW": 0.05, "SAFE": 0}
OCCURRENCE_CAP = 6


def score_findings(findings: list[Finding]) -> dict:
    """Quantum readiness score, 0 (urgent migration) to 100 (quantum-ready)."""
    deduction = 0.0
    counts = {s: 0 for s in WEIGHTS}
    for f in findings:
        counts[f.severity] += 1
        extra = min(max(len(f.occurrences) - 1, 0), OCCURRENCE_CAP)
        deduction += WEIGHTS[f.severity] + extra * OCCURRENCE_BONUS[f.severity]
    score = max(0, round(100 - deduction))
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 55 else "D" if score >= 35 else "F")
    headline = {
        "A": "Quantum-ready posture. Maintain crypto-agility and monitor PQC standards.",
        "B": "Largely sound, with isolated quantum-vulnerable usage to migrate.",
        "C": "Meaningful quantum exposure. Begin a structured PQC migration plan.",
        "D": "Significant harvest-now-decrypt-later exposure. Prioritise key-establishment migration.",
        "F": "Critical quantum exposure across the codebase. Immediate migration planning required.",
    }[grade]
    return {"score": score, "grade": grade, "headline": headline, "counts": counts}


def write_json(obj: dict, path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
