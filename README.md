# QuantumShield

**Post-quantum cryptographic discovery, CBOM generation, and quantum readiness scoring.**

QuantumShield scans a codebase or filesystem for cryptographic usage, parses
certificates and key material, and answers the first question of any PQC
migration: *what quantum-vulnerable cryptography do we actually have, and where?*

It emits a **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)** and a
self-contained HTML report with a 0-100 quantum readiness score.

## Quick start

```bash
pip install -e ".[certs]"
quantumshield scan /path/to/repo -o results/
```

Outputs:

| File | What it is |
|---|---|
| `results/cbom.cdx.json` | CycloneDX 1.6 CBOM — `cryptographic-asset` components with evidence (file + line), OIDs, NIST quantum security levels |
| `results/report.html` | Self-contained report: readiness score, exposure spectrum, per-finding remediation guidance |

Exit code is `1` when CRITICAL findings exist, so it drops straight into CI as
a quantum-exposure gate:

```yaml
- name: PQC exposure gate
  run: quantumshield scan . --json-only
```

Try it on the included fixture:

```bash
quantumshield scan examples/vulnerable-demo -o demo-results/
```

### Live TLS probing

`probe` performs a real TLS handshake against one or more `host:port`
targets and reports the negotiated protocol, cipher suite, and — for TLS 1.3
targets — the negotiated key-exchange group, including hybrid PQC groups
(e.g. `X25519MLKEM768`). Findings flow through the same CBOM/scoring/report
pipeline as `scan`.

```bash
quantumshield probe example.com:443 legacy-host:443 -o probe-results/
```

```
QuantumShield v0.2.0 — probing 2 target(s) ...
  Targets probed: 2 | reachable: 2
  Quantum readiness: 92/100 (grade A)
    HIGH     1
    example.com:443       TLSv1.3 | TLS_AES_256_GCM_SHA384 | group=X25519MLKEM768
    legacy-host:443       TLSv1.1 | ECDHE-RSA-AES256-SHA | group=unknown (TLS<1.3)
```

## What it detects

- **Source code** (Python, JS/TS, Java, Go, C/C++, Rust, C#, Ruby, PHP, and more):
  RSA, ECC/ECDSA/ECDH, DH, DSA, MD5, SHA-1, DES/3DES, RC4, Blowfish, AES
  (by key size), SHA-2/SHA-3 family, ChaCha20 — plus **positive detection of
  PQC adoption** (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+)
- **Config files**: weak TLS protocol versions and cipher suites in nginx,
  Apache, sshd, OpenSSL configs
- **Certificates & keys**: parses X.509 (PEM/DER) for public key algorithm,
  key size, signature algorithm, and expiry; flags quantum-vulnerable private
  key material on disk (header detection only — private keys are never parsed)
- **Live TLS handshakes** (`probe`): negotiated protocol version, cipher
  suite, and — for TLS 1.3 — key-exchange group, including hybrid PQC groups
  (`X25519MLKEM768`, IANA group id `0x11ec`/4588)

## Severity model

| Severity | Meaning | Examples |
|---|---|---|
| CRITICAL | Shor-breakable on a CRQC; harvest-now-decrypt-later exposure | RSA, ECDSA, ECDH, DH, DSA, vulnerable certs |
| HIGH | Classically broken or deprecated today | MD5, SHA-1, DES, 3DES, RC4, TLS <= 1.1 |
| MEDIUM | Grover-reduced security margin | AES-128, SHA-224 |
| LOW | Acceptable but monitor | SHA-256 |
| SAFE | Quantum-ready | AES-256, SHA-384/512, SHA-3, ML-KEM, ML-DSA, SLH-DSA |

**Readiness score**: starts at 100; each vulnerable asset deducts a severity
weight plus a capped per-occurrence penalty, so widespread usage scores worse
than a stray import. Grades: A >= 90, B >= 75, C >= 55, D >= 35, else F.

## Development

```bash
pip install -e ".[dev]"
pytest          # 44 tests
```

Architecture, conventions, and roadmap live in [CLAUDE.md](CLAUDE.md) — the
repo is set up for AI-assisted development with Claude Code.

## Roadmap

- [x] **Engine 2 — network**: live TLS handshake probing (protocol, cipher
      suite, key-exchange group, hybrid PQC detection e.g. X25519MLKEM768)
- [ ] AST-based detection to cut false positives and capture key sizes
- [ ] Mosca-inequality migration urgency modelling per asset
- [ ] Dependency/lockfile crypto analysis
- [ ] Multi-repo tracking and CBOM diffing over time

## Known limitations

- Regex detection can miss dynamically constructed algorithm names and may
  flag commented-out code; review evidence lines in the report.
- PKCS#8 (`BEGIN PRIVATE KEY`) headers don't reveal the algorithm without
  parsing, so unlabelled private keys aren't attributed (the matching
  certificate usually is).
- Bare-acronym collisions: some algorithm names double as unrelated business
  acronyms (e.g. `DES` as a partner/service name in comments or docstrings).
  Distinguishing these from real cipher usage needs semantic/AST context that
  regex can't provide reliably — tracked under the AST-based detection
  roadmap item rather than patched with one-off exclusions that would just
  trade false positives for false negatives elsewhere. Review evidence lines
  for any `DES`/`3DES` finding before treating it as a real cipher usage.
- `probe`'s key-exchange group detection only works against TLS 1.3 servers.
  For TLS <= 1.2, the negotiated curve/group is carried in the
  `ServerKeyExchange` handshake message rather than a ServerHello extension,
  which `probe` doesn't parse — those targets still get protocol/cipher
  findings, just no group finding.
- `probe` crafts its own ClientHello and never completes real key exchange
  (the connection is torn down right after reading the ServerHello), so it
  can't detect PQC hybrid groups behind a load balancer or WAF that decides
  differently for a "real" client than for the bare handshake `probe` sends.

## License

MIT
