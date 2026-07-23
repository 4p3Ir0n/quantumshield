"""QuantumShield — dependency and lockfile analysis.

Running the code-detection regexes over a lockfile is actively harmful: a
transitive package called `ecdsa-sig-formatter` got reported as CRITICAL
"ECDSA signature usage", and `"md5": "^2.3.0"` — a version constraint — as
HIGH "MD5 hashing". Neither is a call site, and a CRITICAL that traces back
to a dependency name is how a scanner loses a security team's trust.

So lockfiles and manifests are parsed as what they are: dependency graphs.

Two rules keep this honest:

* **A declared dependency is not proven usage.** Pulling in a library that
  *can* do MD5 says nothing about whether the code calls it. Dependency
  findings are therefore capped — direct dependencies at MEDIUM, transitive
  ones at LOW — so a lockfile can never fail a CI gate on its own. The
  cap only ever makes a finding less severe, so PQC adoption detected in a
  manifest still reports as SAFE.
* **Only packages implying a specific primitive are mapped.** Broad
  libraries (`cryptography`, `openssl`, `node-forge`, `jsonwebtoken`) can do
  anything, so mapping them to one algorithm would just recreate the noise
  this module exists to remove. They are deliberately absent from PACKAGES.
"""

from __future__ import annotations

import json
import os
import re

from .patterns import ALGORITHMS, SEVERITIES

# Lockfiles and manifests we understand. Anything here is parsed as a
# dependency graph and never fed to the code-detection regexes.
LOCKFILE_NAMES = {
    "package-lock.json", "package.json", "yarn.lock",
    "requirements.txt", "Pipfile.lock", "poetry.lock",
    "Cargo.lock", "go.sum", "go.mod", "Gemfile.lock", "composer.lock",
}

# Package name -> algorithm. Curated on purpose: a package earns a place here
# only if its name implies one specific primitive. See the module docstring.
PACKAGES = {
    # --- broken hashes ---
    "md5": "MD5", "md5.js": "MD5", "blueimp-md5": "MD5", "js-md5": "MD5",
    "md-5": "MD5", "md5-hex": "MD5",
    "sha1": "SHA-1", "js-sha1": "SHA-1", "sha-1": "SHA-1",
    # --- broken ciphers ---
    "rc4": "RC4", "arc4": "RC4",
    "des.js": "3DES", "triple-des": "3DES",
    "blowfish": "BLOWFISH", "egoroof-blowfish": "BLOWFISH",
    # --- Shor-breakable public key ---
    "rsa": "RSA", "node-rsa": "RSA", "ursa": "RSA", "jsrsasign": "RSA",
    "ecdsa": "ECDSA", "ecdsa-sig-formatter": "ECDSA", "starkbank-ecdsa": "ECDSA",
    "elliptic": "ECC", "ed25519": "ECC", "ed25519-dalek": "ECC",
    "secp256k1": "ECC", "tiny-secp256k1": "ECC", "curve25519": "ECC",
    "diffie-hellman": "DH", "dh": "DH",
    "dsa": "DSA",
    # --- post-quantum (positive findings) ---
    "pqcrypto": "ML-KEM", "liboqs": "ML-KEM", "liboqs-python": "ML-KEM",
    "oqs": "ML-KEM", "kyber": "ML-KEM", "kyber-py": "ML-KEM",
    "pqc-kyber": "ML-KEM", "crystals-kyber": "ML-KEM", "ml-kem": "ML-KEM",
    "dilithium": "ML-DSA", "crystals-dilithium": "ML-DSA", "ml-dsa": "ML-DSA",
    "sphincs": "SLH-DSA", "slh-dsa": "SLH-DSA",
}

# A dependency is weaker evidence than a call site, so cap how severe it can be.
DIRECT_CAP = "MEDIUM"
TRANSITIVE_CAP = "LOW"


def is_lockfile(filename: str) -> bool:
    return os.path.basename(filename) in LOCKFILE_NAMES


def normalise(name: str) -> str:
    """Reduce a package identifier to a bare comparable name.

    Handles npm scopes (`@scope/pkg`), Go module paths
    (`github.com/user/pkg`), and Python extras (`pkg[extra]`).
    """
    name = name.strip().strip('"\'').lower()
    if not name:
        return ""
    if "[" in name:                       # requirements.txt extras
        name = name.split("[", 1)[0]
    if name.startswith("@"):              # npm scope: @scope/name -> name
        name = name.split("/", 1)[-1]
    elif "/" in name:                     # go module path -> last segment
        name = name.rstrip("/").split("/")[-1]
    name = re.sub(r"^v\d+$", "", name)    # go major-version suffix
    return name.strip()


def _cap(severity: str, cap: str) -> str:
    """Return the *less* severe of the two. SEVERITIES runs most→least severe,
    so the larger index wins — which also means SAFE is never downgraded."""
    return SEVERITIES[max(SEVERITIES.index(severity), SEVERITIES.index(cap))]


class Dependency:
    __slots__ = ("name", "version", "direct", "line")

    def __init__(self, name: str, version: str = "", direct: bool = True, line: int = 1):
        self.name = name
        self.version = version
        self.direct = direct
        self.line = line


# ------------------------------------------------------------------ parsers
def _parse_package_json(text: str) -> list[Dependency]:
    data = json.loads(text)
    out = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, ver in (data.get(key) or {}).items():
            out.append(Dependency(name, str(ver), direct=True))
    return out


def _parse_package_lock(text: str) -> list[Dependency]:
    data = json.loads(text)
    out = []
    # lockfileVersion 2/3: flat `packages` map keyed by install path.
    packages = data.get("packages")
    if isinstance(packages, dict):
        root_direct = set()
        root = packages.get("")
        if isinstance(root, dict):
            for key in ("dependencies", "devDependencies", "optionalDependencies"):
                root_direct.update((root.get(key) or {}).keys())
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue
            name = path.split("node_modules/")[-1]
            out.append(Dependency(name, str(meta.get("version", "")),
                                  direct=name in root_direct))
    # lockfileVersion 1: nested `dependencies`.
    deps = data.get("dependencies")
    if isinstance(deps, dict) and not packages:
        def walk(node, depth=0):
            for name, meta in node.items():
                if not isinstance(meta, dict):
                    continue
                out.append(Dependency(name, str(meta.get("version", "")),
                                      direct=depth == 0))
                if isinstance(meta.get("dependencies"), dict):
                    walk(meta["dependencies"], depth + 1)
        walk(deps)
    return out


def _parse_yarn_lock(text: str) -> list[Dependency]:
    out = []
    # Entry headers look like:  "pkg@^1.0.0", pkg@^2:
    for i, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#") or line[0].isspace():
            continue
        head = line.rstrip(":").split(",")[0].strip().strip('"')
        if "@" in head[1:]:
            name = head[0] + head[1:].rsplit("@", 1)[0]
            out.append(Dependency(name, "", direct=False, line=i))
    return out


def _parse_requirements(text: str) -> list[Dependency]:
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._\-\[\]]+)\s*([<>=!~]=?.*)?$", line)
        if m:
            out.append(Dependency(m.group(1), (m.group(2) or "").strip(),
                                  direct=True, line=i))
    return out


def _parse_pipfile_lock(text: str) -> list[Dependency]:
    data = json.loads(text)
    out = []
    for section, direct in (("default", True), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            ver = meta.get("version", "") if isinstance(meta, dict) else ""
            out.append(Dependency(name, str(ver), direct=direct))
    return out


def _parse_toml_lock(text: str) -> list[Dependency]:
    """poetry.lock / Cargo.lock — `[[package]]` blocks with `name = "..."`.
    Parsed by line rather than via a TOML library to keep the core stdlib-only
    on Python 3.10, where `tomllib` isn't available."""
    out, name, version, in_pkg = [], None, "", False
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line == "[[package]]":
            if name:
                out.append(Dependency(name, version, direct=False))
            name, version, in_pkg = None, "", True
            continue
        if line.startswith("[") and line != "[[package]]":
            if name:
                out.append(Dependency(name, version, direct=False))
                name, version = None, ""
            in_pkg = False
            continue
        if in_pkg:
            m = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if m:
                name = m.group(1)
                continue
            m = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if m:
                version = m.group(1)
    if name:
        out.append(Dependency(name, version, direct=False))
    return out


def _parse_go(text: str) -> list[Dependency]:
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("//", "module ", "go ")):
            continue
        parts = line.replace("require ", "").replace("(", "").replace(")", "").split()
        if len(parts) >= 2 and "/" in parts[0]:
            out.append(Dependency(parts[0], parts[1], direct=False, line=i))
    return out


def _parse_gemfile_lock(text: str) -> list[Dependency]:
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s{4,6}([a-zA-Z0-9_\-]+)\s*(\([^)]*\))?$", raw)
        if m:
            out.append(Dependency(m.group(1), (m.group(2) or "").strip("()"),
                                  direct=False, line=i))
    return out


def _parse_composer_lock(text: str) -> list[Dependency]:
    data = json.loads(text)
    out = []
    for section in ("packages", "packages-dev"):
        for meta in (data.get(section) or []):
            if isinstance(meta, dict) and meta.get("name"):
                out.append(Dependency(meta["name"], str(meta.get("version", "")),
                                      direct=False))
    return out


PARSERS = {
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "requirements.txt": _parse_requirements,
    "Pipfile.lock": _parse_pipfile_lock,
    "poetry.lock": _parse_toml_lock,
    "Cargo.lock": _parse_toml_lock,
    "go.sum": _parse_go,
    "go.mod": _parse_go,
    "Gemfile.lock": _parse_gemfile_lock,
    "composer.lock": _parse_composer_lock,
}


def parse_dependencies(filename: str, text: str) -> list[Dependency]:
    """Parse a lockfile/manifest into dependencies. Returns [] if the file
    isn't one we understand or is malformed — a broken lockfile should not
    abort a scan."""
    parser = PARSERS.get(os.path.basename(filename))
    if parser is None:
        return []
    try:
        return parser(text)
    except Exception:  # noqa: BLE001 - malformed lockfile, just skip it
        return []


# ----------------------------------------------------------------- findings
class DepFinding:
    """A crypto-relevant dependency, mapped onto the algorithm knowledge base."""

    __slots__ = ("algorithm", "severity", "package", "version", "direct",
                 "line", "note", "nist_qsl", "primitive", "oid")

    def __init__(self, algorithm, severity, package, version, direct, line,
                 note, nist_qsl, primitive, oid):
        self.algorithm = algorithm
        self.severity = severity
        self.package = package
        self.version = version
        self.direct = direct
        self.line = line
        self.note = note
        self.nist_qsl = nist_qsl
        self.primitive = primitive
        self.oid = oid

    @property
    def hint(self) -> str:
        kind = "direct" if self.direct else "transitive"
        ver = f"@{self.version}" if self.version else ""
        return f"{kind} dependency {self.package}{ver}"

    @property
    def snippet(self) -> str:
        ver = f" {self.version}" if self.version else ""
        return f"{self.package}{ver}"


def detect(filename: str, text: str) -> list[DepFinding]:
    """Map a lockfile's dependencies onto crypto findings."""
    findings, seen = [], set()
    for dep in parse_dependencies(filename, text):
        algo = PACKAGES.get(normalise(dep.name))
        if algo is None:
            continue
        key = (algo, normalise(dep.name), dep.direct)
        if key in seen:
            continue
        seen.add(key)
        meta = ALGORITHMS[algo]
        severity = _cap(meta["severity"], DIRECT_CAP if dep.direct else TRANSITIVE_CAP)
        kind = "Direct" if dep.direct else "Transitive"
        if meta["severity"] == "SAFE":
            note = (f"{kind} dependency on {dep.name} indicates {algo} adoption. "
                    f"{meta['note']}")
        else:
            note = (f"{kind} dependency on {dep.name} can perform {algo}. A declared "
                    f"dependency is not proof of use — confirm at the call sites "
                    f"before treating this as exposure. {meta['note']}")
        findings.append(DepFinding(
            algorithm=algo, severity=severity, package=dep.name,
            version=dep.version, direct=dep.direct, line=dep.line, note=note,
            nist_qsl=meta["nist_qsl"], primitive=meta["primitive"],
            oid=meta.get("oid")))
    return findings
