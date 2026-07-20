"""Tests for quantumshield.js_detect — AST-based JavaScript crypto detection.

esprima is an optional dependency; every test skips cleanly if it isn't
installed, so the suite still passes in a core-only environment.
"""

import pytest

from quantumshield.js_detect import HAVE_ESPRIMA, detect
from quantumshield.scanner import Scanner

pytestmark = pytest.mark.skipif(not HAVE_ESPRIMA, reason="esprima (quantumshield[js]) not installed")


def algos(src):
    return {f.algorithm for f in detect(src, src.splitlines())}


def hint_for(src, algorithm):
    for f in detect(src, src.splitlines()):
        if f.algorithm == algorithm:
            return f.hint
    return None


def scan_js(tmp_path, content, filename="app.js"):
    (tmp_path / filename).write_text(content)
    return {f.algorithm for f in Scanner(str(tmp_path)).scan()}


# ------------------------------------------------------- node crypto module
def test_detects_createhash_md5():
    assert "MD5" in algos("const h = crypto.createHash('md5');\n")


def test_detects_createcipheriv_aes256():
    assert "AES-256" in algos("const c = crypto.createCipheriv('aes-256-gcm', k, iv);\n")


def test_detects_createcipheriv_des_variants():
    assert "3DES" in algos("const c = crypto.createCipheriv('des-ede3-cbc', k, iv);\n")
    assert "DES" in algos("const c = crypto.createCipheriv('des-cbc', k, iv);\n")


def test_detects_createcipheriv_rc4():
    # The common, real-world RC4: a recognised API call (vs a hand-rolled
    # implementation, which AST intentionally does not detect).
    assert "RC4" in algos("const c = crypto.createDecipheriv('rc4', key, '');\n")


def test_detects_createecdh_with_curve():
    h = hint_for("const e = crypto.createECDH('prime256v1');\n", "ECDH")
    assert "prime256v1" in h


def test_detects_rsa_keypair_with_modulus_length():
    src = "const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });\n"
    assert "RSA" in algos(src)
    assert "modulusLength=3072" in hint_for(src, "RSA")


def test_detects_ec_keypair():
    assert "ECC" in algos("const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });\n")


# --------------------------------------------------------------- WebCrypto
def test_detects_webcrypto_aes_gcm_length():
    src = "const k = crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);\n"
    assert "AES-256" in algos(src)


def test_detects_webcrypto_rsa_oaep():
    src = "const k = crypto.subtle.importKey('spki', bytes, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);\n"
    found = algos(src)
    assert "RSA" in found and "SHA-256" in found


def test_detects_webcrypto_pbkdf2_hash():
    src = ("const dk = crypto.subtle.deriveKey({ name: 'PBKDF2', salt: s, iterations: 1e5, "
           "hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);\n")
    found = algos(src)
    assert "SHA-256" in found and "AES-256" in found


def test_detects_webcrypto_ecdsa():
    src = "const s = crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, key, data);\n"
    found = algos(src)
    assert "ECDSA" in found and "SHA-384" in found


# --------------------------------------------------------------- JWT / PQC
def test_detects_jwt_rs256():
    assert "RSA" in algos("const t = jwt.sign(payload, priv, { algorithm: 'RS256' });\n")


def test_detects_jwt_es256():
    assert "ECDSA" in algos("const t = jwt.sign(payload, priv, { algorithm: 'ES256' });\n")


def test_detects_pqc_marker_in_string():
    assert "ML-KEM" in algos("const kem = new MlKem768('ml-kem-768');\n")


# ----------------------------------------------------- false-positive kills
def test_algorithm_keyword_in_comment_not_flagged():
    src = ("// we removed DES and RC4 last year, migrated off MD5 too\n"
           "const x = 1;\n")
    assert algos(src) == set()


def test_algorithm_keyword_in_string_literal_not_flagged():
    assert "RC4" not in algos("const label = 'legacy RC4 export (deprecated)';\n")


def test_unrelated_createhash_lookalike_variable():
    # A non-crypto call named similarly must not trip a hash finding.
    assert algos("const h = obj.createHashtag('trending');\n") == set()


# ------------------------------------------------------- scanner integration
def test_scanner_uses_js_ast(tmp_path):
    found = scan_js(tmp_path, "const c = crypto.createCipheriv('aes-256-gcm', k, iv);\n")
    assert "AES-256" in found


def test_scanner_js_comment_false_positive_fixed(tmp_path):
    found = scan_js(tmp_path, "// TODO: rip out the old DES path\nconst x = 1;\n")
    assert "DES" not in found


def test_scanner_ts_file_still_uses_regex(tmp_path):
    # esprima doesn't parse TypeScript, so .ts stays on regex, which still
    # catches the keyword.
    found = scan_js(tmp_path, "const c: Cipher = createCipheriv('rc4', k, iv);\n", filename="a.ts")
    assert "RC4" in found
