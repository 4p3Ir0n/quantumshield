"""QuantumShield — discovery engine 1: filesystem scanner.

Walks a directory, detecting:
  * cryptographic algorithm usage in source code and config files (regex KB)
  * weak TLS protocol configuration
  * X.509 certificates and private keys (parsed with `cryptography` if available)
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .patterns import (ALGORITHMS, PATTERNS, WEAK_PROTOCOLS, CODE_EXTENSIONS,
                       CONFIG_EXTENSIONS, CONFIG_FILENAMES, CERT_EXTENSIONS,
                       SKIP_DIRS, MAX_FILE_BYTES, SEVERITIES)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
    HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False


@dataclass
class Occurrence:
    path: str
    line: int
    snippet: str
    hint: str


@dataclass
class Finding:
    """One cryptographic asset (algorithm/cert/protocol) with all its occurrences."""
    algorithm: str
    asset_type: str          # "algorithm" | "certificate" | "protocol" | "related-crypto-material"
    severity: str
    nist_qsl: int
    primitive: str
    note: str
    oid: str | None = None
    detail: str = ""
    occurrences: list[Occurrence] = field(default_factory=list)


PROTO_RE = re.compile(
    r"(ssl_protocols\s+[^;]*?|SSLProtocol\s+.*?|MinProtocol\s*=\s*|Protocols?\s*=?\s*)"
    r".*?(SSLv2|SSLv3|TLSv1\.1|TLSv1\.0|TLSv1(?![\._0-9]))", re.IGNORECASE)

CERT_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)

KEY_HEADERS = [("BEGIN RSA PRIVATE KEY", "RSA"),
               ("BEGIN EC PRIVATE KEY", "ECC"),
               ("BEGIN DSA PRIVATE KEY", "DSA")]


class Scanner:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self.findings: dict[str, Finding] = {}
        self.files_scanned = 0
        self.certs_parsed = 0

    # ------------------------------------------------------------------ API
    def scan(self) -> list[Finding]:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(full) > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                ext = os.path.splitext(fn)[1].lower()
                if ext in CERT_EXTENSIONS:
                    self._scan_cert_or_key(full)
                elif ext in CODE_EXTENSIONS or ext in CONFIG_EXTENSIONS or fn in CONFIG_FILENAMES:
                    self._scan_text(full)
        return sorted(self.findings.values(),
                      key=lambda f: (SEVERITIES.index(f.severity), f.algorithm))

    # ------------------------------------------------------------ internals
    def _rel(self, path: str) -> str:
        return os.path.relpath(path, self.root)

    def _add(self, key: str, finding_kwargs: dict, occ: Occurrence):
        f = self.findings.get(key)
        if f is None:
            f = Finding(**finding_kwargs)
            self.findings[key] = f
        if not any(o.path == occ.path and o.line == occ.line for o in f.occurrences):
            f.occurrences.append(occ)

    def _scan_text(self, path: str):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except OSError:
            return
        self.files_scanned += 1
        rel = self._rel(path)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or len(stripped) > 800:
                continue
            for algo, rx, hint in PATTERNS:
                if rx.search(stripped):
                    meta = ALGORITHMS[algo]
                    self._add(
                        f"alg:{algo}",
                        dict(algorithm=algo, asset_type="algorithm",
                             severity=meta["severity"], nist_qsl=meta["nist_qsl"],
                             primitive=meta["primitive"], note=meta["note"],
                             oid=meta.get("oid")),
                        Occurrence(rel, i, stripped[:160], hint))
            m = PROTO_RE.search(stripped)
            if m:
                proto = m.group(2)
                norm = "TLSv1.0" if proto.lower() in ("tlsv1", "tlsv1.0") else proto
                sev = WEAK_PROTOCOLS.get(norm, "HIGH")
                self._add(
                    f"proto:{norm}",
                    dict(algorithm=norm, asset_type="protocol", severity=sev,
                         nist_qsl=0, primitive="protocol",
                         note=f"{norm} is deprecated. Configure TLS 1.2 minimum and plan "
                              f"TLS 1.3 with hybrid PQC key exchange (X25519MLKEM768)."),
                    Occurrence(rel, i, stripped[:160], "legacy TLS protocol enabled"))

    # ------------------------------------------------------- cert handling
    def _scan_cert_or_key(self, path: str):
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            return
        self.files_scanned += 1
        rel = self._rel(path)
        text = blob.decode("utf-8", errors="ignore")

        # Private key material on disk — header sniff only, never parse private keys
        for header, algo in KEY_HEADERS:
            if header in text:
                meta = ALGORITHMS[algo]
                self._add(
                    f"key:{algo}",
                    dict(algorithm=f"{algo} private key", asset_type="related-crypto-material",
                         severity=meta["severity"], nist_qsl=0,
                         primitive="private-key", note=meta["note"], oid=meta.get("oid")),
                    Occurrence(rel, 1, header, "quantum-vulnerable key material on disk"))
                break

        if not HAVE_CRYPTOGRAPHY:
            return

        certs = []
        for m in CERT_BLOCK_RE.finditer(text):
            try:
                certs.append(x509.load_pem_x509_certificate(m.group(0).encode()))
            except Exception:
                pass
        if not certs and path.lower().endswith(".der"):
            try:
                certs.append(x509.load_der_x509_certificate(blob))
            except Exception:
                pass

        for cert in certs:
            self.certs_parsed += 1
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                algo, detail = "RSA", f"RSA-{pub.key_size}"
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                algo, detail = "ECC", f"ECDSA {pub.curve.name}"
            elif isinstance(pub, dsa.DSAPublicKey):
                algo, detail = "DSA", f"DSA-{pub.key_size}"
            elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                algo, detail = "ECC", "EdDSA"
            else:
                algo, detail = "ECC", type(pub).__name__
            meta = ALGORITHMS[algo]
            try:
                expiry = cert.not_valid_after_utc.date().isoformat()
            except AttributeError:  # older cryptography versions
                expiry = cert.not_valid_after.date().isoformat()
            subject = cert.subject.rfc4514_string()[:80]
            sig = cert.signature_algorithm_oid._name
            self._add(
                f"cert:{rel}:{cert.serial_number}",
                dict(algorithm=f"X.509 certificate ({detail})", asset_type="certificate",
                     severity=meta["severity"], nist_qsl=0, primitive="certificate",
                     oid=meta.get("oid"),
                     note=f"Certificate public key is quantum-vulnerable ({detail}). "
                          f"Track for replacement with PQC or hybrid certificates as CA "
                          f"support matures.",
                     detail=f"{subject} | sig: {sig} | expires {expiry}"),
                Occurrence(rel, 1, subject, "X.509 certificate"))
