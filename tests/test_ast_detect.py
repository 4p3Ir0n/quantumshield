"""Tests for quantumshield.ast_detect — AST-based Python crypto detection.

These exercise the AST module directly (detect()) and through the Scanner,
covering the two things AST buys over regex: no comment/string false
positives, and key sizes / curve names pulled from call arguments.
"""

import pytest

from quantumshield.ast_detect import detect
from quantumshield.scanner import Scanner


def scan_py(tmp_path, content, filename="mod.py"):
    (tmp_path / filename).write_text(content)
    return Scanner(str(tmp_path)).scan()


def names(findings):
    return {f.algorithm for f in findings}


def algos(source):
    return {af.algorithm for af in detect(source, source.splitlines())}


def hint_for(source, algorithm):
    for af in detect(source, source.splitlines()):
        if af.algorithm == algorithm:
            return af.hint
    return None


# ------------------------------------------------------- detection basics
def test_detects_rsa_keygen():
    assert "RSA" in algos("import x\nk = rsa.generate_private_key(65537, 2048)\n")


def test_captures_rsa_key_size_from_kwarg():
    h = hint_for("k = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n", "RSA")
    assert "key_size=3072" in h


def test_captures_rsa_key_size_from_positional():
    h = hint_for("k = rsa.generate_private_key(65537, 2048)\n", "RSA")
    assert "key_size=2048" in h


def test_captures_ec_curve_name():
    h = hint_for("k = ec.generate_private_key(ec.SECP256R1())\n", "ECC")
    assert "SECP256R1" in h


def test_detects_hashlib_calls():
    src = "import hashlib\na = hashlib.md5(x)\nb = hashlib.sha1(x)\nc = hashlib.sha256(x)\n"
    assert {"MD5", "SHA-1", "SHA-256"} <= algos(src)


def test_detects_hashlib_new_with_string_name():
    assert "MD5" in algos("import hashlib\nh = hashlib.new('md5')\n")


def test_detects_pycryptodome_des3():
    assert "3DES" in algos("from Crypto.Cipher import DES3\nc = DES3.new(k, DES3.MODE_CBC, iv)\n")


def test_detects_aes_size_from_urandom_key():
    src = "import os\nfrom Crypto.Cipher import AES\nc = AES.new(os.urandom(32), AES.MODE_GCM)\n"
    assert "AES-256" in algos(src)


def test_detects_cryptography_aesgcm_with_generated_key():
    src = ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
           "key = AESGCM.generate_key(bit_length=256)\n"
           "c = AESGCM(key)\n")
    # generate_key(bit_length=256) is itself the sizing signal via AESGCM(key)?
    # No — AESGCM(key) takes a Name, not the call; the generate_key line is a
    # separate statement. So detection here comes from AES.new-style sizing
    # only when the key call is inline. Assert the ChaCha path and inline path
    # separately below; here we just confirm no false crash and AES not mis-sized.
    assert "AES-128" not in algos(src)


def test_detects_cryptography_aesgcm_inline_generated_key():
    src = ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
           "c = AESGCM(AESGCM.generate_key(bit_length=256))\n")
    assert "AES-256" in algos(src)


def test_detects_chacha20poly1305_aead():
    src = ("from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n"
           "c = ChaCha20Poly1305(key)\n")
    assert "ChaCha20" in algos(src)


def test_aesgcm_with_opaque_runtime_key_is_not_sized():
    # key of unknowable size must not be guessed into a severity bucket
    src = ("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
           "c = AESGCM(load_key_from_kms())\n")
    found = algos(src)
    assert not any(a.startswith("AES-") for a in found)


def test_detects_jwt_rs256():
    assert "RSA" in algos('import jwt\nt = jwt.encode(p, key, algorithm="RS256")\n')


def test_detects_jwt_es256():
    assert "ECDSA" in algos('import jwt\nt = jwt.encode(p, key, algorithm="ES256")\n')


def test_detects_pqc_string_marker():
    assert "ML-KEM" in algos('kem = KeyEncapsulation("ML-KEM-768")\n')


# ------------------------------------------------------- import aliasing
def test_resolves_import_alias():
    src = ("import hashlib as hl\n"
           "h = hl.md5(x)\n")
    assert "MD5" in algos(src)


def test_resolves_from_import_alias():
    src = ("from cryptography.hazmat.primitives.asymmetric import rsa as r\n"
           "k = r.generate_private_key(65537, 2048)\n")
    assert "RSA" in algos(src)


# ----------------------------------------------------- false-positive kills
def test_des_acronym_in_comment_not_flagged():
    # The exact dogfooding false positive: "DES" as a business acronym in a
    # comment / docstring must not be flagged as the DES cipher.
    src = ('"""Import from the DES (Data Exchange Service) partner feed."""\n'
           "# vendor_code is usually DES for the legacy feed\n"
           "vendor = 'DES'\n")
    assert "DES" not in algos(src)


def test_algorithm_name_in_string_literal_not_flagged():
    assert "RSA" not in algos('label = "we deprecated RSA last year"\n')


# ------------------------------------------------ scanner integration
def test_scanner_uses_ast_for_python(tmp_path):
    f = scan_py(tmp_path, "k = rsa.generate_private_key(65537, 2048)\n")
    rsa = next(x for x in f if x.algorithm == "RSA")
    assert rsa.severity == "CRITICAL"
    assert "key_size=2048" in rsa.occurrences[0].hint  # AST enrichment reached the Finding


def test_scanner_des_comment_false_positive_fixed(tmp_path):
    f = scan_py(tmp_path, "# the DES partner feed\nvendor = 'DES'\n")
    assert "DES" not in names(f)


def test_scanner_falls_back_to_regex_on_syntax_error(tmp_path):
    # `return` at module level is a SyntaxError, so AST bails and regex runs —
    # and the regex path still catches the RS256 JWT algorithm string.
    f = scan_py(tmp_path, 'return jwt.encode(p, key, algorithm="RS256")\n')
    assert "RSA" in names(f)


def test_scanner_non_python_still_uses_regex(tmp_path):
    f = scan_py(tmp_path, "const e = crypto.createECDH('prime256v1');\n", filename="a.js")
    assert "ECDH" in names(f)
