"""Tests for quantumshield.deps — lockfile / dependency analysis.

The regression these guard against is real and was found by scanning a live
project: a transitive package named `ecdsa-sig-formatter` was reported as
CRITICAL "ECDSA signature usage", and `"md5": "^2.3.0"` — a version
constraint — as HIGH "MD5 hashing".
"""

import json

from quantumshield.deps import (
    DIRECT_CAP, TRANSITIVE_CAP, detect, is_lockfile, normalise,
    parse_dependencies,
)
from quantumshield.scanner import Scanner

PKG_LOCK_V3 = json.dumps({
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"md5": "^2.3.0"}},
        "node_modules/md5": {"version": "2.3.0"},
        "node_modules/ecdsa-sig-formatter": {"version": "1.0.11"},
        "node_modules/left-pad": {"version": "1.3.0"},
    },
})


def algos(findings):
    return {f.algorithm for f in findings}


def by_algo(findings, algo):
    return next(f for f in findings if f.algorithm == algo)


# ------------------------------------------------------------ file routing
def test_is_lockfile_recognises_known_names():
    for name in ("package-lock.json", "requirements.txt", "go.sum", "Cargo.lock",
                 "yarn.lock", "Gemfile.lock", "poetry.lock"):
        assert is_lockfile(name)
    assert is_lockfile("/deep/path/package-lock.json")


def test_is_lockfile_rejects_ordinary_files():
    assert not is_lockfile("app.py")
    assert not is_lockfile("settings.json")


# ------------------------------------------------------------- normalising
def test_normalise_handles_scopes_paths_and_extras():
    assert normalise("@scope/elliptic") == "elliptic"
    assert normalise("github.com/user/ecdsa") == "ecdsa"
    assert normalise("cryptography[ssh]") == "cryptography"
    assert normalise('  "MD5"  ') == "md5"


# ----------------------------------------------------------------- parsers
def test_parse_package_lock_v3_direct_vs_transitive():
    deps = {d.name: d for d in parse_dependencies("package-lock.json", PKG_LOCK_V3)}
    assert deps["md5"].direct is True and deps["md5"].version == "2.3.0"
    assert deps["ecdsa-sig-formatter"].direct is False


def test_parse_package_lock_v1_nested():
    text = json.dumps({"lockfileVersion": 1, "dependencies": {
        "elliptic": {"version": "6.5.4", "dependencies": {"md5": {"version": "2.3.0"}}}}})
    deps = {d.name: d for d in parse_dependencies("package-lock.json", text)}
    assert deps["elliptic"].direct is True
    assert deps["md5"].direct is False


def test_parse_package_json():
    text = json.dumps({"dependencies": {"md5": "^2.3.0"},
                       "devDependencies": {"elliptic": "^6.0.0"}})
    deps = {d.name for d in parse_dependencies("package.json", text)}
    assert deps == {"md5", "elliptic"}


def test_parse_requirements_txt():
    text = ("# comment\n\npycryptodome==3.19.0\nrsa>=4.9\n"
            "ecdsa\n-r other.txt\ncryptography[ssh]==42.0\n")
    deps = {d.name for d in parse_dependencies("requirements.txt", text)}
    assert {"rsa", "ecdsa", "pycryptodome"} <= deps
    assert not any(d.startswith("-") for d in deps)


def test_parse_go_sum():
    text = ("github.com/foo/ecdsa v1.2.3 h1:abc=\n"
            "golang.org/x/crypto v0.17.0/go.mod h1:def=\n")
    deps = {d.name for d in parse_dependencies("go.sum", text)}
    assert "github.com/foo/ecdsa" in deps


def test_parse_cargo_lock():
    text = '[[package]]\nname = "md-5"\nversion = "0.10.6"\n\n[[package]]\nname = "serde"\nversion = "1.0"\n'
    deps = {d.name: d.version for d in parse_dependencies("Cargo.lock", text)}
    assert deps["md-5"] == "0.10.6" and "serde" in deps


def test_parse_yarn_lock():
    text = 'md5@^2.3.0:\n  version "2.3.0"\n\n"@scope/elliptic@^6.0.0":\n  version "6.5.4"\n'
    deps = {d.name for d in parse_dependencies("yarn.lock", text)}
    assert "md5" in deps


def test_malformed_lockfile_is_skipped_not_fatal():
    assert parse_dependencies("package-lock.json", "{not valid json") == []


def test_unknown_lockfile_returns_nothing():
    assert parse_dependencies("mystery.lock", "anything") == []


# ---------------------------------------------------------------- findings
def test_detects_crypto_packages_and_ignores_others():
    findings = detect("package-lock.json", PKG_LOCK_V3)
    assert algos(findings) == {"MD5", "ECDSA"}      # left-pad is not crypto


def test_dependency_findings_are_capped_below_critical():
    """The core regression: a dependency name must never produce a CRITICAL
    that fails a build."""
    findings = detect("package-lock.json", PKG_LOCK_V3)
    assert all(f.severity not in ("CRITICAL",) for f in findings)
    # ECDSA is CRITICAL as a call site, but transitive here -> capped to LOW
    assert by_algo(findings, "ECDSA").severity == TRANSITIVE_CAP
    # MD5 is HIGH as a call site, but a direct dependency -> capped to MEDIUM
    assert by_algo(findings, "MD5").severity == DIRECT_CAP


def test_safe_algorithms_are_not_downgraded_by_the_cap():
    # The cap only ever makes findings *less* severe, so detected PQC adoption
    # still reports as SAFE rather than being dragged down to LOW.
    findings = detect("requirements.txt", "liboqs-python==0.10.0\n")
    assert by_algo(findings, "ML-KEM").severity == "SAFE"


def test_finding_hint_names_the_package_and_directness():
    findings = detect("package-lock.json", PKG_LOCK_V3)
    assert "transitive dependency ecdsa-sig-formatter@1.0.11" == by_algo(findings, "ECDSA").hint
    assert "direct dependency md5@2.3.0" == by_algo(findings, "MD5").hint


def test_note_says_a_dependency_is_not_proof_of_use():
    note = by_algo(detect("package-lock.json", PKG_LOCK_V3), "ECDSA").note
    assert "not proof of use" in note


def test_broad_crypto_libraries_are_deliberately_unmapped():
    # Mapping `cryptography`/`node-forge`/`jsonwebtoken` to one algorithm would
    # recreate the noise this module exists to remove.
    for pkg in ("cryptography==42.0\n", "openssl==1.1\n", "pyjwt==2.8.0\n"):
        assert detect("requirements.txt", pkg) == []


# ------------------------------------------------------- scanner integration
def test_scanner_reports_lockfile_deps_not_call_sites(tmp_path):
    (tmp_path / "package-lock.json").write_text(PKG_LOCK_V3)
    findings = Scanner(str(tmp_path)).scan()
    assert {f.algorithm for f in findings} == {"MD5 (dependency)", "ECDSA (dependency)"}
    assert all(f.asset_type == "dependency" for f in findings)
    assert all(f.severity != "CRITICAL" for f in findings)


def test_scanner_finds_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text("ecdsa==0.18.0\n")
    findings = Scanner(str(tmp_path)).scan()
    assert findings and findings[0].algorithm == "ECDSA (dependency)"


# ------------------------------------------- data-JSON false positive fix
def test_algorithm_names_in_data_json_are_not_flagged(tmp_path):
    """Regression: mock data describing crypto ("encryption": "AES-128") was
    reported as usage. A string value is a description, not a call site."""
    (tmp_path / "mock_assets.json").write_text(json.dumps(
        [{"asset": "db", "encryption": "AES-128"},
         {"asset": "api", "encryption": "SHA-1"},
         {"asset": "vault", "encryption": "AES-256"}]))
    assert Scanner(str(tmp_path)).scan() == []


def test_code_files_still_flag_the_same_algorithms(tmp_path):
    # Control: the fix must not blunt detection in actual code.
    (tmp_path / "a.py").write_text("import hashlib\nh = hashlib.sha1(b'x')\n")
    assert {f.algorithm for f in Scanner(str(tmp_path)).scan()} == {"SHA-1"}


def test_weak_protocol_directives_still_detected_in_json(tmp_path):
    # Protocol detection keys off specific config directives, not bare names,
    # so it stays enabled for JSON.
    (tmp_path / "cfg.json").write_text('{"tls": "ssl_protocols TLSv1.1;"}')
    protos = [f for f in Scanner(str(tmp_path)).scan() if f.asset_type == "protocol"]
    assert protos and protos[0].algorithm == "TLSv1.1"
