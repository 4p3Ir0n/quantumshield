"""QuantumShield — AST-based JavaScript crypto-usage detection.

Same idea as ast_detect.py (Python), for JS: walk a real parse tree so
detection fires only on genuine call sites, never on keywords in comments or
strings, and pull structured detail (RSA modulusLength, WebCrypto AES key
length, hash names) out of call arguments.

Uses `esprima` (a pure-Python JS parser), which is an OPTIONAL dependency
(`pip install "quantumshield[js]"`). If esprima isn't installed, or a file
uses syntax esprima can't parse (esprima targets ES2017 — modern TS/JSX,
top-level await, optional chaining, etc. will fail), the scanner falls back
to the regex patterns for that file. Only .js/.mjs/.cjs are routed here;
.ts/.tsx/.jsx stay on regex since esprima doesn't handle TypeScript or JSX.
"""

from __future__ import annotations

from dataclasses import dataclass

try:
    import esprima
    HAVE_ESPRIMA = True
except ImportError:  # optional dependency
    esprima = None
    HAVE_ESPRIMA = False


@dataclass
class JSFinding:
    algorithm: str
    lineno: int
    snippet: str
    hint: str


# ------------------------------------------------------- string classifiers
def classify_hash(name: str | None) -> str | None:
    if not name:
        return None
    n = name.lower().replace("-", "").replace("_", "")
    # Exact SHA-2 / MD5 names first: "sha384" is SHA-384, NOT a SHA-3 variant.
    direct = {
        "md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256",
        "sha384": "SHA-384", "sha512": "SHA-512",
    }
    if n in direct:
        return direct[n]
    # SHA-3 family: bare "sha3", the sha3-NNN variants, SHAKE, or Keccak.
    if n == "sha3" or n in ("sha3224", "sha3256", "sha3384", "sha3512") \
            or n.startswith("shake") or "keccak" in n:
        return "SHA-3"
    return None


def classify_cipher(name: str | None) -> tuple[str | None, str | None]:
    """Return (algorithm, detail) for an OpenSSL-style cipher string like
    'aes-256-gcm', 'des-ede3-cbc', 'rc4'."""
    if not name:
        return None, None
    n = name.lower()
    if "aes" in n:
        for bits in ("256", "192", "128"):
            if bits in n:
                return f"AES-{bits}", None
        return None, None  # AES of unstated size — don't guess a severity
    if "des-ede3" in n or "des3" in n or "3des" in n or "des-ede" in n:
        return "3DES", None
    if n.startswith("des") or "-des-" in n or n == "des":
        return "DES", None
    if "rc4" in n:
        return "RC4", None
    if n.startswith("bf") or "blowfish" in n:
        return "BLOWFISH", None
    if "chacha20" in n:
        return "ChaCha20", None
    return None, None


# WebCrypto SubtleCrypto algorithm `name` -> our algorithm id
WEBCRYPTO_ALGO = {
    "rsa-oaep": "RSA", "rsa-pss": "RSA", "rsassa-pkcs1-v1_5": "RSA",
    "ecdsa": "ECDSA", "ecdh": "ECDH",
}
# generateKeyPairSync('type', ...) first-arg type -> algorithm id
KEYPAIR_TYPE = {
    "rsa": "RSA", "rsa-pss": "RSA", "ec": "ECC", "ed25519": "ECC", "ed448": "ECC",
    "x25519": "ECC", "x448": "ECC", "dsa": "DSA", "dh": "DH",
}
PQC_MARKERS = {
    "ML-KEM": ("mlkem", "ml-kem", "kyber"),
    "ML-DSA": ("mldsa", "ml-dsa", "dilithium"),
    "SLH-DSA": ("slhdsa", "slh-dsa", "sphincs"),
}


# ------------------------------------------------------------- AST helpers
def _member_name(node) -> str | None:
    """`a.b.c` MemberExpression -> 'a.b.c'; Identifier -> its name."""
    parts = []
    while node is not None and node.type == "MemberExpression":
        prop = node.property
        parts.append(prop.name if prop.type == "Identifier" else
                     (str(prop.value) if prop.type == "Literal" else "?"))
        node = node.object
    if node is not None and node.type == "Identifier":
        parts.append(node.name)
        return ".".join(reversed(parts))
    return None


def _literal_str(node) -> str | None:
    if node is not None and node.type == "Literal" and isinstance(node.value, str):
        return node.value
    return None


def _object_props(node) -> dict:
    """Flatten an ObjectExpression to a dict. Nested objects recurse; the
    common `hash` case (string or {name: 'SHA-256'}) is normalised to a str."""
    out = {}
    if node is None or node.type != "ObjectExpression":
        return out
    for p in node.properties:
        if getattr(p, "type", None) != "Property":
            continue
        key = (p.key.name if p.key.type == "Identifier" else
               p.key.value if p.key.type == "Literal" else None)
        if key is None:
            continue
        v = p.value
        if v.type == "Literal":
            out[key] = v.value
        elif v.type == "ObjectExpression":
            nested = _object_props(v)
            out[key] = nested.get("name", nested)
        # other value types (identifiers, calls) left out — not statically usable
    return out


def _walk_calls(node, out):
    """Collect every CallExpression / NewExpression node in the tree."""
    if node is None or not hasattr(node, "type"):
        return
    if node.type in ("CallExpression", "NewExpression"):
        out.append(node)
    for key in vars(node):
        val = getattr(node, key)
        if isinstance(val, list):
            for item in val:
                _walk_calls(item, out)
        elif hasattr(val, "type"):
            _walk_calls(val, out)


# --------------------------------------------------------------- detection
class _Detector:
    def __init__(self, lines: list[str]):
        self.lines = lines
        self.findings: list[JSFinding] = []

    def _snippet(self, node) -> str:
        line = node.loc.start.line if node.loc else 0
        idx = line - 1
        return self.lines[idx].strip()[:160] if 0 <= idx < len(self.lines) else ""

    def _emit(self, algo: str, node, hint: str):
        line = node.loc.start.line if node.loc else 0
        self.findings.append(JSFinding(algo, line, self._snippet(node), hint))

    def analyse(self, call):
        callee = _member_name(call.callee)
        method = callee.split(".")[-1] if callee else ""
        args = call.arguments

        self._pqc_markers(call, args)

        if method in ("createHash", "createHmac"):
            algo = classify_hash(_literal_str(args[0]) if args else None)
            if algo:
                self._emit(algo, call, f"{algo} via {method} (JS AST)")
        elif method in ("createCipheriv", "createCipher", "createDecipheriv", "createDecipher"):
            algo, _ = classify_cipher(_literal_str(args[0]) if args else None)
            if algo:
                self._emit(algo, call, f"{algo} via {method} (JS AST)")
        elif method == "createECDH":
            curve = _literal_str(args[0]) if args else None
            self._emit("ECDH", call, "EC key agreement via createECDH (JS AST)" +
                       (f", curve={curve}" if curve else ""))
        elif method in ("createDiffieHellman", "createDiffieHellmanGroup"):
            self._emit("DH", call, f"Diffie-Hellman via {method} (JS AST)")
        elif method in ("generateKeyPairSync", "generateKeyPair"):
            self._keypair(call, args)
        elif method in ("generateKey", "importKey", "deriveKey", "deriveBits",
                        "encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"):
            self._webcrypto(call, args)
            self._jwt(call, args)  # jwt.sign/verify also land here
        elif method in ("sign", "verify", "decode"):
            self._jwt(call, args)

    def _keypair(self, call, args):
        kind = (_literal_str(args[0]) if args else "") or ""
        algo = KEYPAIR_TYPE.get(kind.lower())
        if not algo:
            return
        detail = ""
        opts = _object_props(args[1]) if len(args) > 1 else {}
        if algo == "RSA" and isinstance(opts.get("modulusLength"), int):
            detail = f", modulusLength={opts['modulusLength']}"
        elif kind:
            detail = f", type={kind}"
        self._emit(algo, call, f"{algo} keypair via generateKeyPair (JS AST){detail}")

    def _webcrypto(self, call, args):
        for arg in args:
            if getattr(arg, "type", None) != "ObjectExpression":
                continue
            props = _object_props(arg)
            name = props.get("name")
            if not isinstance(name, str):
                continue
            low = name.lower()
            algo = WEBCRYPTO_ALGO.get(low)
            if algo:
                self._emit(algo, call, f"WebCrypto {name} (JS AST)")
            elif low.startswith("aes"):
                length = props.get("length")
                if length in (128, 192, 256):
                    self._emit(f"AES-{length}", call, f"WebCrypto {name}, length={length} (JS AST)")
            # a `hash` sub-parameter (HMAC/PBKDF2/RSA-PSS) names a digest too
            h = classify_hash(props.get("hash") if isinstance(props.get("hash"), str) else None)
            if h:
                self._emit(h, call, f"WebCrypto {name} hash={props.get('hash')} (JS AST)")

    def _jwt(self, call, args):
        for arg in args:
            if getattr(arg, "type", None) != "ObjectExpression":
                continue
            props = _object_props(arg)
            alg = props.get("algorithm") or props.get("algorithms")
            if not isinstance(alg, str):
                continue
            prefix = alg.upper()[:2]
            if prefix in ("RS", "PS"):
                self._emit("RSA", call, f"JWT/JOSE {alg.upper()} signing (JS AST)")
            elif prefix == "ES":
                self._emit("ECDSA", call, f"JWT/JOSE {alg.upper()} signing (JS AST)")

    def _pqc_markers(self, call, args):
        for arg in args:
            s = _literal_str(arg)
            if not s:
                continue
            low = s.lower()
            for algo, markers in PQC_MARKERS.items():
                if any(m in low for m in markers):
                    self._emit(algo, call, f"{algo} usage (JS AST)")
                    return


def detect(source: str, lines: list[str]) -> list[JSFinding]:
    """Parse JS `source` and return AST-detected crypto findings.

    Raises RuntimeError if esprima isn't installed, or the parser's error if
    `source` doesn't parse — callers should fall back to regex in both cases.
    """
    if not HAVE_ESPRIMA:
        raise RuntimeError("esprima not installed; install quantumshield[js]")
    try:
        tree = esprima.parseModule(source, {"loc": True})
    except esprima.Error:
        tree = esprima.parseScript(source, {"loc": True})  # retry as a script
    calls = []
    _walk_calls(tree, calls)
    detector = _Detector(lines)
    for call in calls:
        detector.analyse(call)
    return detector.findings
