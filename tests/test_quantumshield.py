"""QuantumShield test suite."""

import json
import os
import subprocess
import sys

import pytest

from quantumshield.scanner import Scanner
from quantumshield.cbom import build_cbom, score_findings


def scan_source(tmp_path, filename, content):
    (tmp_path / filename).write_text(content)
    return Scanner(str(tmp_path)).scan()


def names(findings):
    return {f.algorithm for f in findings}


# ------------------------------------------------------------- detection
def test_detects_rsa_python(tmp_path):
    f = scan_source(tmp_path, "a.py", "key = rsa.generate_private_key(65537, 2048)\n")
    assert "RSA" in names(f)
    assert f[0].severity == "CRITICAL"
    assert f[0].nist_qsl == 0


def test_detects_md5_and_sha1(tmp_path):
    f = scan_source(tmp_path, "a.py",
                    "import hashlib\nh1 = hashlib.md5(d)\nh2 = hashlib.sha1(d)\n")
    assert {"MD5", "SHA-1"} <= names(f)


def test_detects_jwt_rs256_as_rsa(tmp_path):
    # Algorithm string alone implies RSA signing even with no local keygen
    # call at this call site (key commonly loaded from a vault/PEM file).
    f = scan_source(tmp_path, "auth.py",
                    'return jwt.encode(payload, private_pem, algorithm="RS256")\n')
    assert "RSA" in names(f)


def test_detects_jwt_es256_as_ecdsa(tmp_path):
    f = scan_source(tmp_path, "auth.js",
                    "jwt.sign(payload, privateKey, { algorithm: 'ES256' });\n")
    assert "ECDSA" in names(f)


def test_jwt_algorithm_lookalike_not_flagged(tmp_path):
    # word-boundary guard: a similarly-shaped token that isn't an actual
    # JWT alg value (e.g. a SKU/model number) must not match.
    f = scan_source(tmp_path, "a.py", 'model = "PS2560-XL"\n')
    assert "RSA" not in names(f)


def test_detects_ecdh_js(tmp_path):
    f = scan_source(tmp_path, "a.js", "const e = crypto.createECDH('prime256v1');\n")
    assert "ECDH" in names(f)


def test_detects_weak_tls_protocol(tmp_path):
    f = scan_source(tmp_path, "nginx.conf", "ssl_protocols TLSv1.1 TLSv1.2;\n")
    protos = [x for x in f if x.asset_type == "protocol"]
    assert protos and protos[0].algorithm == "TLSv1.1" and protos[0].severity == "HIGH"


def test_detects_pqc_positively(tmp_path):
    f = scan_source(tmp_path, "a.py", 'kem = KeyEncapsulation("ML-KEM-768")\n')
    mlkem = [x for x in f if x.algorithm == "ML-KEM"]
    assert mlkem and mlkem[0].severity == "SAFE"


def test_occurrence_evidence_has_file_and_line(tmp_path):
    f = scan_source(tmp_path, "a.py", "# padding\nh = hashlib.md5(d)\n")
    md5 = next(x for x in f if x.algorithm == "MD5")
    assert md5.occurrences[0].path == "a.py"
    assert md5.occurrences[0].line == 2


# --------------------------------------------------------- false positives
def test_lowercase_des_variable_not_flagged(tmp_path):
    f = scan_source(tmp_path, "Main.java",
                    'Cipher des = Cipher.getInstance("DESede/CBC/PKCS5Padding");\n')
    assert "DES" not in names(f)
    assert "3DES" in names(f)


def test_description_word_not_flagged_as_des(tmp_path):
    f = scan_source(tmp_path, "a.py", "# des is short for description here\ndes = 1\n")
    assert "DES" not in names(f)


def test_negated_cipher_in_suite_string_not_flagged(tmp_path):
    # `!MD5` (and `!DES`, `!RC4`, ...) in an OpenSSL-style cipher-suite string
    # *excludes* the weak algorithm; it must not be reported as usage.
    f = scan_source(tmp_path, "nginx.conf", "ssl_ciphers HIGH:!aNULL:!MD5;\n")
    assert "MD5" not in names(f)


def test_negated_des_in_cipher_suite_not_flagged(tmp_path):
    f = scan_source(tmp_path, "nginx.conf", "ssl_ciphers HIGH:!aNULL:!DES:!RC4;\n")
    assert "DES" not in names(f)
    assert "RC4" not in names(f)


def test_skips_node_modules(tmp_path):
    nm = tmp_path / "node_modules"
    nm.mkdir()
    (nm / "x.js").write_text("crypto.createHash('md5')\n")
    assert Scanner(str(tmp_path)).scan() == []


# ----------------------------------------------------------------- certs
def test_parses_rsa_certificate(tmp_path):
    cryptography = pytest.importorskip("cryptography")
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.internal")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    (tmp_path / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    f = Scanner(str(tmp_path)).scan()
    certs = [x for x in f if x.asset_type == "certificate"]
    assert certs and "RSA-2048" in certs[0].algorithm and certs[0].severity == "CRITICAL"


# ---------------------------------------------------------------- scoring
def test_clean_pqc_project_scores_100(tmp_path):
    f = scan_source(tmp_path, "modern.py",
                    'kem = KeyEncapsulation("ML-KEM-768")\nh = hashlib.sha512(b"x")\n')
    s = score_findings(f)
    assert s["score"] == 100 and s["grade"] == "A"


def test_vulnerable_project_scores_low(tmp_path):
    f = scan_source(tmp_path, "bad.py",
                    "k = rsa.generate_private_key(65537, 2048)\n"
                    "e = ec.generate_private_key(ec.SECP256R1())\n"
                    "h = hashlib.md5(d)\n")
    s = score_findings(f)
    assert s["counts"]["CRITICAL"] == 2
    assert s["score"] < 75


def test_more_occurrences_score_worse(tmp_path):
    one = score_findings(scan_source(tmp_path, "a.py", "hashlib.md5(x)\n"))
    many_src = "\n".join(f"h{i} = hashlib.md5(x{i})" for i in range(5))
    d2 = tmp_path / "many"
    d2.mkdir()
    many = score_findings(scan_source(d2, "b.py", many_src + "\n"))
    assert many["score"] < one["score"]


# ------------------------------------------------------------------- CBOM
def test_cbom_is_cyclonedx_16(tmp_path):
    f = scan_source(tmp_path, "a.py", "k = rsa.generate_private_key(65537)\n")
    bom = build_cbom(f, "target", score_findings(f))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    rsa_comp = next(c for c in bom["components"] if c["name"] == "RSA")
    assert rsa_comp["type"] == "cryptographic-asset"
    assert rsa_comp["cryptoProperties"]["assetType"] == "algorithm"
    assert rsa_comp["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert rsa_comp["evidence"]["occurrences"][0]["location"] == "a.py"


# -------------------------------------------------------------------- CLI
def test_cli_exit_1_on_critical(tmp_path):
    (tmp_path / "bad.py").write_text("k = rsa.generate_private_key(65537)\n")
    r = subprocess.run([sys.executable, "-m", "quantumshield", "scan", str(tmp_path),
                        "-o", str(tmp_path / "out"), "--json-only"],
                       capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert r.returncode == 1
    assert (tmp_path / "out" / "cbom.cdx.json").exists()
    json.load(open(tmp_path / "out" / "cbom.cdx.json"))


def test_cli_exit_0_when_clean(tmp_path):
    (tmp_path / "ok.py").write_text('h = hashlib.sha512(b"x")\n')
    r = subprocess.run([sys.executable, "-m", "quantumshield", "scan", str(tmp_path),
                        "-o", str(tmp_path / "out"), "--json-only"],
                       capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert r.returncode == 0
