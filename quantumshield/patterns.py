"""QuantumShield — algorithm knowledge base and detection patterns.

Each detected usage maps to an entry in ALGORITHMS, which carries the
quantum-threat metadata used for CBOM generation and risk scoring.

nist_qsl = NIST quantum security level (0 = no quantum security).
threat   = primary quantum attack vector: "shor" | "grover" | "none".
"""

import re

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]

ALGORITHMS = {
    # ----- Shor-breakable public-key crypto (harvest-now-decrypt-later) -----
    "RSA": dict(primitive="pke", threat="shor", nist_qsl=0, severity="CRITICAL",
                oid="1.2.840.113549.1.1.1",
                note="Broken by Shor's algorithm on a CRQC. Encrypted traffic is exposed to "
                     "harvest-now-decrypt-later. Migrate to ML-KEM (FIPS 203) for key "
                     "establishment or ML-DSA (FIPS 204) for signatures."),
    "ECDSA": dict(primitive="signature", threat="shor", nist_qsl=0, severity="CRITICAL",
                  oid="1.2.840.10045.4.3.2",
                  note="Elliptic-curve signatures are Shor-breakable. Migrate to ML-DSA "
                       "(FIPS 204) or SLH-DSA (FIPS 205)."),
    "ECDH": dict(primitive="key-agree", threat="shor", nist_qsl=0, severity="CRITICAL",
                 oid="1.3.132.1.12",
                 note="EC key agreement is Shor-breakable; session keys derived today can be "
                      "recovered later. Migrate to ML-KEM or a hybrid (e.g. X25519MLKEM768)."),
    "ECC": dict(primitive="pke", threat="shor", nist_qsl=0, severity="CRITICAL",
                oid="1.2.840.10045.2.1",
                note="Elliptic-curve cryptography is Shor-breakable. Plan migration to "
                     "NIST PQC standards (FIPS 203/204/205)."),
    "DH": dict(primitive="key-agree", threat="shor", nist_qsl=0, severity="CRITICAL",
               oid="1.2.840.113549.1.3.1",
               note="Finite-field Diffie-Hellman is Shor-breakable. Migrate to ML-KEM or "
                    "hybrid key establishment."),
    "DSA": dict(primitive="signature", threat="shor", nist_qsl=0, severity="CRITICAL",
                oid="1.2.840.10040.4.1",
                note="DSA is Shor-breakable and deprecated classically. Migrate to ML-DSA."),

    # ----- Classically broken / deprecated -----
    "MD5": dict(primitive="hash", threat="grover", nist_qsl=0, severity="HIGH",
                oid="1.2.840.113549.2.5",
                note="Classically broken (practical collisions). Replace with SHA-256+ or "
                     "SHA-3 regardless of quantum timeline."),
    "SHA-1": dict(primitive="hash", threat="grover", nist_qsl=0, severity="HIGH",
                  oid="1.3.14.3.2.26",
                  note="Classically broken for collision resistance (SHAttered). Replace "
                       "with SHA-256+ or SHA-3."),
    "DES": dict(primitive="block-cipher", threat="grover", nist_qsl=0, severity="HIGH",
                oid="1.3.14.3.2.7",
                note="56-bit key; classically brute-forceable. Replace with AES-256."),
    "3DES": dict(primitive="block-cipher", threat="grover", nist_qsl=0, severity="HIGH",
                 oid="1.2.840.113549.3.7",
                 note="Deprecated by NIST (SWEET32, 64-bit blocks). Replace with AES-256."),
    "RC4": dict(primitive="stream-cipher", threat="grover", nist_qsl=0, severity="HIGH",
                oid="1.2.840.113549.3.4",
                note="Classically broken stream cipher. Replace with AES-GCM or ChaCha20."),
    "BLOWFISH": dict(primitive="block-cipher", threat="grover", nist_qsl=0, severity="HIGH",
                     oid=None,
                     note="64-bit block cipher (SWEET32-class risk). Replace with AES-256."),

    # ----- Grover-affected symmetric / hash -----
    "AES-128": dict(primitive="block-cipher", threat="grover", nist_qsl=1, severity="MEDIUM",
                    oid="2.16.840.1.101.3.4.1.2",
                    note="Grover's algorithm halves effective strength to ~64 bits. NIST "
                         "still rates AES-128 at QSL 1, but new systems should prefer AES-256."),
    "AES-192": dict(primitive="block-cipher", threat="grover", nist_qsl=3, severity="LOW",
                    oid="2.16.840.1.101.3.4.1.22",
                    note="Adequate post-quantum margin; AES-256 preferred for new builds."),
    "SHA-224": dict(primitive="hash", threat="grover", nist_qsl=1, severity="MEDIUM",
                    oid="2.16.840.1.101.3.4.2.4",
                    note="Reduced collision margin under quantum attack; prefer SHA-384+."),
    "SHA-256": dict(primitive="hash", threat="grover", nist_qsl=2, severity="LOW",
                    oid="2.16.840.1.101.3.4.2.1",
                    note="Acceptable post-quantum (QSL 2). Prefer SHA-384 for long-lived "
                         "signatures."),

    # ----- Quantum-resistant -----
    "AES-256": dict(primitive="block-cipher", threat="grover", nist_qsl=5, severity="SAFE",
                    oid="2.16.840.1.101.3.4.1.42",
                    note="QSL 5 — recommended symmetric cipher."),
    "SHA-384": dict(primitive="hash", threat="grover", nist_qsl=4, severity="SAFE",
                    oid="2.16.840.1.101.3.4.2.2", note="QSL 4 — recommended."),
    "SHA-512": dict(primitive="hash", threat="grover", nist_qsl=5, severity="SAFE",
                    oid="2.16.840.1.101.3.4.2.3", note="QSL 5 — recommended."),
    "SHA-3": dict(primitive="hash", threat="grover", nist_qsl=4, severity="SAFE",
                  oid="2.16.840.1.101.3.4.2.8", note="Quantum-resistant hash family."),
    "ChaCha20": dict(primitive="stream-cipher", threat="grover", nist_qsl=5, severity="SAFE",
                     oid=None, note="256-bit key; strong post-quantum margin."),
    "ML-KEM": dict(primitive="kem", threat="none", nist_qsl=3, severity="SAFE",
                   oid="2.16.840.1.101.3.4.4.2",
                   note="FIPS 203 post-quantum KEM (Kyber). Quantum-resistant."),
    "ML-DSA": dict(primitive="signature", threat="none", nist_qsl=3, severity="SAFE",
                   oid="2.16.840.1.101.3.4.3.17",
                   note="FIPS 204 post-quantum signature (Dilithium). Quantum-resistant."),
    "SLH-DSA": dict(primitive="signature", threat="none", nist_qsl=3, severity="SAFE",
                    oid="2.16.840.1.101.3.4.3.20",
                    note="FIPS 205 stateless hash-based signature (SPHINCS+). Quantum-resistant."),
}

WEAK_PROTOCOLS = {
    "SSLv2": "CRITICAL", "SSLv3": "CRITICAL",
    "TLSv1": "HIGH", "TLSv1.0": "HIGH", "TLSv1.1": "HIGH",
}


def _c(p):
    return re.compile(p, re.IGNORECASE)


PATTERNS = [
    # --- RSA ---
    ("RSA", _c(r"rsa\.generate_private_key|RSA\.generate\s*\(|generateKeyPairSync?\(\s*['\"]rsa|"
               r"Cipher\.getInstance\(\s*\"RSA|KeyPairGenerator\.getInstance\(\s*\"RSA|"
               r"crypto/rsa|ssh-rsa|new RSACryptoServiceProvider|OpenSSL::PKey::RSA"),
     "RSA key generation / encryption"),
    ("RSA", _c(r"BEGIN RSA (PRIVATE|PUBLIC) KEY"), "RSA key material on disk"),

    # --- ECC family ---
    ("ECDSA", _c(r"\bECDSA\b|ecdsa\.|SigningKey\.generate|signature\.ECDSA|getInstance\(\s*\"(SHA\d+withECDSA|EC)\""),
     "ECDSA signature usage"),
    ("ECDH", _c(r"createECDH|\bECDH\b|ec\.ECDH|\bX25519\b|\bX448\b"), "EC key agreement"),
    ("ECC", _c(r"ec\.generate_private_key|SECP\d+[RK]\d|secp\d+[rk]\d|prime256v1|"
               r"ed25519|Ed25519|BEGIN EC PRIVATE KEY|\belliptic\b"),
     "elliptic-curve key material"),

    # --- DH / DSA ---
    ("DH", _c(r"dh\.generate_parameters|createDiffieHellman|\bDHE-|getInstance\(\s*\"(DH|DiffieHellman)\""),
     "Diffie-Hellman key agreement"),
    ("DSA", _c(r"\bdsa\.generate_private_key|getInstance\(\s*\"DSA\"|BEGIN DSA PRIVATE KEY"),
     "DSA usage"),

    # --- Broken hashes / ciphers ---
    ("MD5", _c(r"hashlib\.md5|\bMD5\b|createHash\(\s*['\"]md5|Digest::MD5|md5sum"), "MD5 hashing"),
    ("SHA-1", _c(r"hashlib\.sha1|\bSHA-?1\b(?![0-9])|createHash\(\s*['\"]sha1|getInstance\(\s*\"SHA-1\""), "SHA-1 hashing"),
    # bare-word DES must be uppercase (avoids matching variables named `des`)
    ("DES", _c(r"(?-i:\bDES\b(?!ede|3|-CBC3|cendant))|getInstance\(\s*\"DES[\"/]|createCipheriv\(\s*['\"]des(?!-ede)"),
     "single DES"),
    ("3DES", _c(r"3DES|DESede|TripleDES|DES3|DES-EDE|DES-CBC3"), "Triple-DES"),
    ("RC4", _c(r"\bRC4\b|\bARC4\b|ARCFOUR"), "RC4 stream cipher"),
    ("BLOWFISH", _c(r"\bblowfish\b|\bBF-CBC\b"), "Blowfish"),

    # --- AES with explicit key sizes ---
    ("AES-128", _c(r"aes-?128|AES_128|AES/.{0,20}128"), "AES-128"),
    ("AES-192", _c(r"aes-?192|AES_192"), "AES-192"),
    ("AES-256", _c(r"aes-?256|AES_256"), "AES-256"),

    # --- Hashes ---
    ("SHA-224", _c(r"sha-?224"), "SHA-224"),
    ("SHA-256", _c(r"hashlib\.sha256|sha-?256|createHash\(\s*['\"]sha256"), "SHA-256"),
    ("SHA-384", _c(r"sha-?384"), "SHA-384"),
    ("SHA-512", _c(r"hashlib\.sha512|sha-?512(?!/)"), "SHA-512"),
    ("SHA-3", _c(r"sha3[-_]|SHA-3|keccak"), "SHA-3 / Keccak"),
    ("ChaCha20", _c(r"chacha20"), "ChaCha20"),

    # --- Post-quantum (positive findings) ---
    ("ML-KEM", _c(r"ML-?KEM|kyber|mlkem"), "ML-KEM / Kyber (PQC)"),
    ("ML-DSA", _c(r"ML-?DSA|dilithium|mldsa"), "ML-DSA / Dilithium (PQC)"),
    ("SLH-DSA", _c(r"SLH-?DSA|sphincs"), "SLH-DSA / SPHINCS+ (PQC)"),
]

CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".go", ".rb", ".cs",
    ".cpp", ".cc", ".c", ".h", ".hpp", ".rs", ".php", ".swift", ".scala",
    ".sh", ".ps1", ".pl", ".m",
}
CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".tf", ".env", ".properties"}
CONFIG_FILENAMES = {"sshd_config", "ssh_config", "nginx.conf", "httpd.conf", "openssl.cnf", "Dockerfile"}
CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".p12", ".pfx", ".pub"}

SKIP_DIRS = {".git", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
             "dist", "build", ".idea", ".vscode", "vendor", ".terraform", "site-packages"}

MAX_FILE_BYTES = 2 * 1024 * 1024
