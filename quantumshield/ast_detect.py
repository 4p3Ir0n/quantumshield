"""QuantumShield — AST-based Python crypto-usage detection.

Regex matches keywords wherever they appear on a line, including inside
comments, docstrings, and unrelated string literals — the source of the
DES-as-business-acronym false positive documented in README's "Known
limitations" (dogfooding found "DES" used as a partner/service name in a
comment, which the bare-word DES pattern can't tell apart from real usage).

Walking the AST instead means we only ever look at genuine call sites,
resolved through the file's own import aliases, and can pull structured
detail (key sizes, EC curve names) straight out of call arguments — which
regex can't do at all.

Only used for .py files that parse cleanly; scanner.py falls back to the
regex patterns for files that don't parse (or aren't Python).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

# --- crypto call recognition rules -----------------------------------------
# Keys are dotted call-path *suffixes* matched against the call's resolved
# name (see _matches_rule) — e.g. "rsa.generate_private_key" matches both
# `rsa.generate_private_key(...)` and `Crypto.Foo.rsa.generate_private_key(...)`.

# algorithm, human label, size-extraction strategy
KEYGEN_RULES = {
    "rsa.generate_private_key": ("RSA", "RSA key generation", "key_size"),
    "RSA.generate": ("RSA", "RSA key generation", "size_pos0"),
    "dsa.generate_private_key": ("DSA", "DSA key generation", "key_size"),
    "dh.generate_parameters": ("DH", "DH parameter generation", "key_size"),
}
EC_KEYGEN_RULES = {"ec.generate_private_key"}
HASH_CALL_RULES = {
    "hashlib.md5": "MD5", "hashlib.sha1": "SHA-1", "hashlib.sha224": "SHA-224",
    "hashlib.sha256": "SHA-256", "hashlib.sha384": "SHA-384", "hashlib.sha512": "SHA-512",
    "hashlib.sha3_256": "SHA-3", "hashlib.sha3_384": "SHA-3", "hashlib.sha3_512": "SHA-3",
}
HASHLIB_NEW_NAME_MAP = {
    "md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256",
    "sha384": "SHA-384", "sha512": "SHA-512",
}
CIPHER_NEW_RULES = {
    "DES.new": "DES", "DES3.new": "3DES", "ARC4.new": "RC4", "Blowfish.new": "BLOWFISH",
    "AES.new": "AES",  # size resolved separately, from the key argument
}
# `cryptography` library AEAD constructors. Value "AES" needs a key size
# (resolved from the argument where statically visible; skipped otherwise).
AEAD_RULES = {
    "AESGCM": "AES", "AESCCM": "AES", "AESGCMSIV": "AES",
    "AESSIV": "AES", "AESOCB3": "AES",
    "ChaCha20Poly1305": "ChaCha20",
}
RANDOM_BYTES_RULES = {"os.urandom", "get_random_bytes", "secrets.token_bytes"}
# calls that yield a key of a statically-known size, keyed by how to read it
GENERATE_KEY_SUFFIX = "generate_key"  # cryptography AEADs: generate_key(bit_length=N)
PQC_ARG_MARKERS = {
    "ML-KEM": ("mlkem", "ml-kem", "kyber"),
    "ML-DSA": ("mldsa", "ml-dsa", "dilithium"),
    "SLH-DSA": ("slhdsa", "slh-dsa", "sphincs"),
}


@dataclass
class ASTFinding:
    algorithm: str
    lineno: int
    snippet: str
    hint: str


# ---------------------------------------------------------- name resolution
def _dotted_chain(node: ast.expr) -> list[str] | None:
    """`a.b.c` -> ['a', 'b', 'c']; None if the base isn't a plain Name."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return list(reversed(parts))
    return None


class _ImportAliases(ast.NodeVisitor):
    """Maps each locally-bound name to its fully-qualified origin, so a call
    site resolves correctly even through `import x as y` / `from a.b import
    c as d`."""

    def __init__(self):
        self.aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.aliases[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = alias.name
        self.generic_visit(node)


def _resolve_call_name(func_node: ast.expr, aliases: dict[str, str]) -> str | None:
    chain = _dotted_chain(func_node)
    if not chain:
        return None
    root, *rest = chain
    resolved_root = aliases.get(root, root)
    return ".".join([resolved_root, *rest])


def _matches_rule(resolved: str, rule_key: str) -> bool:
    """Whole-segment suffix match: "Crypto.Cipher.AES.new" matches "AES.new",
    but "MyAES.new" does not (avoids substring false-matches)."""
    r_segs, k_segs = resolved.split("."), rule_key.split(".")
    return len(r_segs) >= len(k_segs) and r_segs[-len(k_segs):] == k_segs


# -------------------------------------------------------------- AST helpers
def _string_const(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _int_const(node) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


# ------------------------------------------------------------ call visitor
class _CryptoCallVisitor(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str], lines: list[str]):
        self.aliases = aliases
        self.lines = lines
        self.findings: list[ASTFinding] = []

    def _snippet(self, node) -> str:
        idx = node.lineno - 1
        return self.lines[idx].strip()[:160] if 0 <= idx < len(self.lines) else ""

    def _kwarg_int(self, node: ast.Call, name: str) -> int | None:
        for kw in node.keywords:
            if kw.arg == name:
                return _int_const(kw.value)
        return None

    def _pos_int(self, node: ast.Call, index: int) -> int | None:
        return _int_const(node.args[index]) if len(node.args) > index else None

    def _kwarg_str(self, node: ast.Call, name: str) -> str | None:
        for kw in node.keywords:
            if kw.arg == name:
                return _string_const(kw.value)
        return None

    def visit_Call(self, node: ast.Call):
        resolved = _resolve_call_name(node.func, self.aliases)
        if resolved:
            self._check_keygen(node, resolved)
            self._check_ec_keygen(node, resolved)
            self._check_hash(node, resolved)
            self._check_cipher_new(node, resolved)
            self._check_aead(node, resolved)
            self._check_jwt_algorithm(node, resolved)
            self._check_pqc_constructor(node)
        self.generic_visit(node)

    def _check_keygen(self, node: ast.Call, resolved: str):
        for rule_key, (algo, label, size_spec) in KEYGEN_RULES.items():
            if not _matches_rule(resolved, rule_key):
                continue
            if size_spec == "size_pos0":
                size = self._pos_int(node, 0)
            else:  # "key_size": try the kwarg, fall back to the conventional 2nd positional arg
                size = self._kwarg_int(node, "key_size")
                if size is None:
                    size = self._pos_int(node, 1)
            hint = f"{label} (AST)" + (f", key_size={size}" if size else "")
            self.findings.append(ASTFinding(algo, node.lineno, self._snippet(node), hint))
            return

    def _check_ec_keygen(self, node: ast.Call, resolved: str):
        if not any(_matches_rule(resolved, k) for k in EC_KEYGEN_RULES):
            return
        curve = self._curve_name(node.args[0]) if node.args else None
        hint = "EC key generation (AST)" + (f", curve={curve}" if curve else "")
        self.findings.append(ASTFinding("ECC", node.lineno, self._snippet(node), hint))

    @staticmethod
    def _curve_name(arg_node) -> str | None:
        func = arg_node.func if isinstance(arg_node, ast.Call) else arg_node
        if isinstance(func, ast.Attribute):
            return func.attr
        if isinstance(func, ast.Name):
            return func.id
        return None

    def _check_hash(self, node: ast.Call, resolved: str):
        for rule_key, algo in HASH_CALL_RULES.items():
            if _matches_rule(resolved, rule_key):
                self.findings.append(ASTFinding(
                    algo, node.lineno, self._snippet(node), f"{algo} hashing (AST)"))
                return
        if _matches_rule(resolved, "hashlib.new") and node.args:
            name = _string_const(node.args[0])
            algo = HASHLIB_NEW_NAME_MAP.get((name or "").lower())
            if algo:
                self.findings.append(ASTFinding(
                    algo, node.lineno, self._snippet(node),
                    f"{algo} hashing via hashlib.new (AST)"))

    def _check_cipher_new(self, node: ast.Call, resolved: str):
        for rule_key, algo in CIPHER_NEW_RULES.items():
            if not _matches_rule(resolved, rule_key):
                continue
            if algo == "AES":
                size_bits = self._aes_key_size_bits(node)
                if size_bits in (128, 192, 256):
                    self.findings.append(ASTFinding(
                        f"AES-{size_bits}", node.lineno, self._snippet(node),
                        f"AES-{size_bits} cipher (AST)"))
                # unknown key size: skip rather than guess a severity bucket
            else:
                self.findings.append(ASTFinding(
                    algo, node.lineno, self._snippet(node), f"{algo} cipher (AST)"))
            return

    def _check_aead(self, node: ast.Call, resolved: str):
        for rule_key, algo in AEAD_RULES.items():
            if not _matches_rule(resolved, rule_key):
                continue
            if algo == "AES":
                size_bits = self._aes_key_size_bits(node)
                if size_bits in (128, 192, 256):
                    self.findings.append(ASTFinding(
                        f"AES-{size_bits}", node.lineno, self._snippet(node),
                        f"AES-{size_bits} AEAD ({rule_key}, AST)"))
                # runtime/opaque key: size unknowable statically, skip rather than guess
            else:
                self.findings.append(ASTFinding(
                    algo, node.lineno, self._snippet(node), f"{algo} AEAD ({rule_key}, AST)"))
            return

    def _aes_key_size_bits(self, node: ast.Call) -> int | None:
        if not node.args or not isinstance(node.args[0], ast.Call):
            return None
        key_call = node.args[0]
        resolved = _resolve_call_name(key_call.func, self.aliases)
        if not resolved:
            return None
        # os.urandom(32) / get_random_bytes(32) / secrets.token_bytes(32) -> bytes*8
        if any(_matches_rule(resolved, r) for r in RANDOM_BYTES_RULES):
            n = _int_const(key_call.args[0]) if key_call.args else None
            return n * 8 if n is not None else None
        # AESGCM.generate_key(bit_length=256) and similar
        if resolved.split(".")[-1] == GENERATE_KEY_SUFFIX:
            return self._kwarg_int(key_call, "bit_length")
        return None

    def _check_jwt_algorithm(self, node: ast.Call, resolved: str):
        if resolved.split(".")[-1] not in ("encode", "sign"):
            return
        alg_value = self._kwarg_str(node, "algorithm")
        if not alg_value:
            return
        prefix = alg_value.upper()[:2]
        if prefix in ("RS", "PS"):
            self.findings.append(ASTFinding(
                "RSA", node.lineno, self._snippet(node),
                f"JWT/JOSE {alg_value.upper()} signing (AST)"))
        elif prefix == "ES":
            self.findings.append(ASTFinding(
                "ECDSA", node.lineno, self._snippet(node),
                f"JWT/JOSE {alg_value.upper()} signing (AST)"))

    def _check_pqc_constructor(self, node: ast.Call):
        for arg in node.args:
            s = _string_const(arg)
            if not s:
                continue
            low = s.lower()
            for algo, markers in PQC_ARG_MARKERS.items():
                if any(m in low for m in markers):
                    self.findings.append(ASTFinding(
                        algo, node.lineno, self._snippet(node), f"{algo} usage (AST)"))
                    return


def detect(source: str, lines: list[str]) -> list[ASTFinding]:
    """Parse `source` and return AST-detected crypto findings.

    Raises SyntaxError (or ValueError, for things like embedded null bytes)
    if `source` doesn't parse as Python — callers should fall back to regex
    detection for that file.
    """
    tree = ast.parse(source)
    aliases = _ImportAliases()
    aliases.visit(tree)
    visitor = _CryptoCallVisitor(aliases.aliases, lines)
    visitor.visit(tree)
    return visitor.findings
