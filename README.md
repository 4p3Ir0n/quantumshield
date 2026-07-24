# QuantumShield

**Post-quantum cryptographic discovery, CBOM generation, and quantum readiness scoring.**

QuantumShield scans a codebase or filesystem for cryptographic usage, parses
certificates and key material, and answers the first question of any PQC
migration: *what quantum-vulnerable cryptography do we actually have, and where?*

It emits a **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)** and a
self-contained HTML report with a 0-100 quantum readiness score.

## Quick start

```bash
pip install quantumshield-pqc          # add [certs], [js], [web], or [all] extras
quantumshield scan /path/to/repo -o results/
```

The PyPI distribution is **`quantumshield-pqc`** (the `quantumshield` name was
already taken); the command and `import quantumshield` are unchanged. Optional
extras: `certs` (X.509 parsing), `js` (JavaScript AST detection via esprima),
`web` (the demo web UI). The core is stdlib-only.

From a source checkout for development:

```bash
pip install -e ".[dev]"
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

Tune the threshold with `--fail-on {critical,high,medium,low,any,never}`.

### Living with a real repository

A first scan of an established codebase finds years of accumulated crypto, most
of which won't be fixed this sprint. Three ways to quieten it, in increasing
precision:

**Baseline** — record what exists today, then gate only on what's *new*. This
is what lets a team adopt the CI gate without fixing the backlog first:

```bash
quantumshield scan . --write-baseline .quantumshield-baseline.json   # once, commit it
quantumshield scan . --baseline .quantumshield-baseline.json         # in CI
```

Fingerprints ignore line numbers, so a baselined finding stays baselined when
unrelated edits push it up or down the file.

**`.quantumshieldignore`** — gitignore-style path globs at the scan root, for
directories that should never be scanned (`!` negation is not supported):

```gitignore
thirdparty/
**/generated/**
*.min.js
```

**Inline suppressions** — per-line, reviewable in code review, and they travel
with the code. Any comment syntax works:

```python
h = hashlib.sha1(data)  # quantumshield: ignore[SHA-1] legacy vendor feed, JIRA-123
```

`ignore` alone suppresses every finding on the line; `ignore[MD5,SHA-1]` limits
it to named algorithms. Everything suppressed is counted in the run summary, so
nothing disappears silently.

### Dependencies are evidence, not proof

A lockfile is a dependency graph, not code. Scanning one with code patterns
reports package *names* as call sites — a transitive package called
`ecdsa-sig-formatter` becomes "CRITICAL ECDSA signature usage", and
`"md5": "^2.3.0"` becomes "HIGH MD5 hashing". Neither is true, and a CRITICAL
that traces to a dependency name is how a scanner loses a security team's
trust.

So lockfiles are parsed structurally, and dependency findings are **capped**:
direct dependencies at MEDIUM, transitive ones at LOW. A dependency can never
fail a CI gate on its own — pulling in a library that *can* do MD5 says nothing
about whether your code calls it. Findings are labelled accordingly:

```
[LOW] ECDSA (dependency)
    package-lock.json:1 -> transitive dependency ecdsa-sig-formatter@1.0.11
    Transitive dependency on ecdsa-sig-formatter can perform ECDSA. A declared
    dependency is not proof of use — confirm at the call sites before treating
    this as exposure.
```

The cap only ever makes findings *less* severe, so PQC adoption found in a
manifest (`liboqs-python`, `kyber`) still reports as SAFE. Broad libraries that
can do anything — `cryptography`, `openssl`, `node-forge`, `jsonwebtoken` — are
deliberately **not** mapped to a single algorithm, since that would recreate the
noise this exists to remove.

### SARIF for code-scanning dashboards

```bash
quantumshield scan . --sarif        # writes results.sarif alongside the CBOM
```

SARIF 2.1.0, so findings land in GitHub code scanning (or any SARIF-consuming
dashboard) with file, line, severity and a stable fingerprint per alert:

```yaml
- run: quantumshield scan . --sarif --fail-on never
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: quantumshield-out/results.sarif
```

SAFE findings are deliberately **not** emitted as SARIF alerts — they're
positive detections (you already use AES-256 / ML-KEM here), and filing them as
alerts would raise bugs against correct code. They remain in the CBOM and HTML
report.

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
QuantumShield v0.5.0 — probing 2 target(s) ...
  Targets probed: 2 | reachable: 2
  Quantum readiness: 92/100 (grade A)
    HIGH     1
    example.com:443       TLSv1.3 | TLS_AES_256_GCM_SHA384 | group=X25519MLKEM768
    legacy-host:443       TLSv1.1 | ECDHE-RSA-AES256-SHA | group=unknown (TLS<1.3)
```

### Demo web UI

A browser front-end for demonstrating a scan: enter a repo path, get the live
dashboard (score, exposure spectrum, per-finding evidence). Needs the `[web]`
extra.

```bash
pip install -e ".[web]"
quantumshield serve                      # http://127.0.0.1:8000, scans confined to cwd
quantumshield serve --root /path/to/code # confine scans elsewhere
```

Routes: `/` (scan form + embedded report), `/report?path=…` (the HTML report),
`/api/scan?path=…` (raw CycloneDX 1.6 CBOM as JSON), `/healthz`.

> **This is a local demo surface, not a service.** It has no authentication and
> returns source-line snippets, so two limits are enforced in code: requested
> paths are confined to `--root` (default: the working directory, with `..` and
> symlink escapes rejected), and it refuses to bind a non-loopback interface
> without `--allow-remote`. Don't expose it to a network you don't control —
> see [SECURITY.md](SECURITY.md).

## What it detects

- **Source code** (Python, JS/TS, Java, Go, C/C++, Rust, C#, Ruby, PHP, and more):
  RSA, ECC/ECDSA/ECDH, DH, DSA, MD5, SHA-1, DES/3DES, RC4, Blowfish, AES
  (by key size), SHA-2/SHA-3 family, ChaCha20 — plus **positive detection of
  PQC adoption** (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+)
- **Python & JS via AST** (not regex): Python files are analysed with the
  stdlib `ast` module, and JavaScript (`.js`/`.mjs`/`.cjs`) with `esprima`
  when the optional `[js]` extra is installed. Detection fires only on real
  call sites — resolved through the file's own import aliases — never on
  keywords in comments or strings, and structured detail is read straight from
  the arguments: RSA key size (`generate_private_key(key_size=3072)`,
  `generateKeyPairSync('rsa', {modulusLength: 3072})`), EC curve names, and
  WebCrypto AES key length. Files that fail to parse fall back to regex.
- **Config files**: weak TLS protocol versions and cipher suites in nginx,
  Apache, sshd, OpenSSL configs
- **Certificates & keys**: parses X.509 (PEM/DER) for public key algorithm,
  key size, signature algorithm, and expiry; flags quantum-vulnerable private
  key material on disk (header detection only — private keys are never parsed)
- **Live TLS handshakes** (`probe`): negotiated protocol version, cipher
  suite, and — for TLS 1.3 — key-exchange group, including hybrid PQC groups
  (`X25519MLKEM768`, IANA group id `0x11ec`/4588)
- **Lockfiles and manifests** (`package-lock.json`, `package.json`,
  `yarn.lock`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`,
  `Cargo.lock`, `go.sum`/`go.mod`, `Gemfile.lock`, `composer.lock`): parsed as
  dependency graphs, distinguishing direct from transitive

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
pytest          # 210 tests
```

Architecture, conventions, and roadmap live in [CLAUDE.md](CLAUDE.md) — the
repo is set up for AI-assisted development with Claude Code.

## Roadmap

- [x] **Engine 2 — network**: live TLS handshake probing (protocol, cipher
      suite, key-exchange group, hybrid PQC detection e.g. X25519MLKEM768)
- [x] AST-based detection (Python + JavaScript) to cut false positives and capture key sizes
- [ ] Mosca-inequality migration urgency modelling per asset
- [x] Dependency/lockfile crypto analysis
- [ ] Multi-repo tracking and CBOM diffing over time

## Known limitations

- Python and JavaScript (`.js`/`.mjs`/`.cjs`, with the `[js]` extra) are
  analysed by AST and don't suffer comment/string false positives. Other
  source — and TypeScript/JSX, which esprima doesn't parse — is matched by
  regex, which can miss dynamically constructed algorithm names and may flag
  keywords in comments or strings; review evidence lines in the report.
- AST detects recognised crypto *API calls*, not hand-rolled implementations:
  a bespoke RC4 written out as array operations won't be flagged (regex would
  catch the keyword, at the cost of false positives). Use a real cipher call
  (`crypto.createCipheriv('rc4', …)`) and it's caught.
- AST detection (Python) reads key sizes from call arguments only when they're
  statically visible. An AES key loaded at runtime (e.g. from a KMS/env) can't
  be sized, so `AESGCM(runtime_key)` is recorded as AES usage but without a
  key-size severity rather than guessing one. Determinable forms
  (`AESGCM(AESGCM.generate_key(bit_length=256))`, `AES.new(os.urandom(32), …)`)
  are sized correctly.
- Bare-acronym collisions (e.g. `DES` as a partner/service name in a comment):
  fixed for Python by AST detection, which only inspects real call sites. The
  same collision can still occur in non-Python source that goes through regex —
  review evidence lines for any `DES`/`3DES` finding there before treating it
  as real cipher usage.
- PKCS#8 (`BEGIN PRIVATE KEY`) headers don't reveal the algorithm without
  parsing, so unlabelled private keys aren't attributed (the matching
  certificate usually is).
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
