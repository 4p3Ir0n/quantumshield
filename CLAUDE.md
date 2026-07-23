# CLAUDE.md — QuantumShield project context

This file is read automatically by Claude Code at the start of every session in
this repo. It carries the full project context so the owner never has to
re-explain it.

## What this project is

QuantumShield is a post-quantum cryptography (PQC) discovery tool: it scans a
codebase/filesystem for cryptographic usage, parses X.509 certificates, emits a
**CycloneDX 1.6 CBOM** (`cryptographic-asset` components with evidence), and
produces a 0–100 **quantum readiness score** plus a self-contained HTML report.
Exit code 1 on CRITICAL findings makes it a CI quantum-exposure gate.

It is v0.5 (discovery engines 1-2 of 4, published to PyPI as `quantumshield-pqc`)
of a larger product vision: a PQC agility
platform (part of the owner's "Ketsig" product family, alongside OT-PQC Scout,
a pcap-based OT/ICS quantum readiness scanner). Target audience: security
engineering teams starting PQC migration; near-term goal is design-partner
conversations, and relevance to India's CBOM mandate (FY 2027-28) and global
PQC migration timelines.

## Architecture

- `quantumshield/patterns.py` — algorithm knowledge base (severity, NIST QSL,
  OID, remediation text) + regex detection patterns. **All detection knowledge
  lives here**; scanner logic stays generic.
- `quantumshield/ast_detect.py` — AST-based Python detection (stdlib `ast`).
  `.py` files that parse cleanly are analysed here instead of by regex:
  precise call-site detection resolved through the file's import aliases, key
  sizes / EC curve names pulled from call args, no comment/string false
  positives. Emits `ASTFinding`s the scanner maps onto the algorithm KB.
- `quantumshield/js_detect.py` — AST-based JavaScript detection via optional
  `esprima` (`[js]` extra). Same idea for `.js`/`.mjs`/`.cjs`: node crypto
  (`createHash`/`createCipheriv`/`generateKeyPairSync`), WebCrypto subtle
  algorithm objects, jwt algorithm strings, PQC markers; modulusLength / AES
  length / curve pulled from args. TS/JSX aren't parsed (→ regex). `HAVE_ESPRIMA`
  gates it; emits `JSFinding`s.
- `quantumshield/scanner.py` — filesystem walk, per-file detection (AST for
  parseable Python & JS, regex otherwise), weak-TLS-protocol detection, X.509
  parsing (via optional `cryptography`). Produces `Finding` objects (one per
  unique asset, with `Occurrence` evidence).
- `quantumshield/webapp.py` — optional demo web UI (FastAPI, `[web]` extra,
  `quantumshield serve`). Thin wrapper over the scanner: `/`, `/report`,
  `/api/scan`, `/healthz`. Reuses `render_report`.
- `quantumshield/tls_probe.py` — discovery engine 2: live TLS handshake
  probing (`probe` command). Protocol/cipher via the stdlib `ssl` module;
  negotiated key-exchange group (incl. hybrid PQC, e.g. X25519MLKEM768) via a
  hand-rolled TLS 1.3 ClientHello/ServerHello, since `ssl` has no API for
  that. Produces the same `Finding`/`Occurrence` objects as the scanner.
- `quantumshield/deps.py` — lockfile/manifest analysis (roadmap item 4). Parses
  the common lockfiles as dependency graphs and maps a *curated* package list
  onto the algorithm KB. Findings are `asset_type="dependency"` and severity-
  capped (direct → MEDIUM, transitive → LOW) so a package name can never
  produce a CRITICAL; the cap is a max-of-indices so SAFE is never downgraded.
  Broad libraries (`cryptography`, `node-forge`, `jsonwebtoken`) are
  intentionally unmapped — mapping them to one algorithm recreates the noise.
- `quantumshield/suppress.py` — noise control: `.quantumshieldignore` globs,
  inline `quantumshield: ignore[ALGO] reason` comments, line-number-independent
  fingerprints, and baseline write/load/apply. `DEFAULT_IGNORE_PATTERNS` stops
  the scanner reading its own CBOM/SARIF/baseline artifacts (they name
  algorithms in plain text, so scanning them re-reports everything).
- `quantumshield/sarif.py` — SARIF 2.1.0 export. One rule per algorithm, one
  result per occurrence, severity → level + `security-severity`. SAFE findings
  are intentionally excluded (positive detections aren't alerts).
- `quantumshield/cbom.py` — CycloneDX 1.6 CBOM builder + scoring engine.
- `quantumshield/report.py` — self-contained HTML report (inline CSS, palette:
  ink #0E1726, bg #F4F7FA, violet #5B4BD4, severity colors in SEV_COLORS).
- `quantumshield/cli.py` — argparse CLI (subparsers): `scan`, `probe`, `serve`.
- `tests/` — `test_quantumshield.py`, `test_tls_probe.py`, `test_ast_detect.py`,
  `test_js_detect.py`, `test_webapp.py`, `test_suppress.py`, `test_sarif.py`,
  `test_cli_gating.py`, `test_deps.py` — 189 pytest tests (JS/web tests skip cleanly when their
  optional deps are absent).

## Conventions and invariants

- Python ≥3.10, stdlib-only core; `cryptography` is optional (cert parsing
  degrades gracefully). Do not add hard dependencies without strong reason.
- Severity model (do not change without discussion):
  CRITICAL = Shor-breakable (RSA/ECC/ECDH/DH/DSA + vulnerable certs/keys),
  HIGH = classically broken (MD5, SHA-1, DES, 3DES, RC4, TLS ≤1.1),
  MEDIUM = Grover-reduced (AES-128, SHA-224), LOW = monitor (SHA-256),
  SAFE = AES-256, SHA-384+, SHA-3, ML-KEM, ML-DSA, SLH-DSA.
- Never parse private keys — header detection only (see `KEY_HEADERS`).
- New detection patterns MUST ship with: a positive test AND a false-positive
  guard test (see `test_lowercase_des_variable_not_flagged` — a real bug we
  caught: bare-word DES must be case-sensitive).
- CBOM must stay valid CycloneDX 1.6; `cryptographic-asset` component type.
- Run `pytest` before considering any change done. CI: `.github/workflows/ci.yml`.
- PyPI distribution name is `quantumshield-pqc` (import/CLI stay `quantumshield`);
  releases publish via trusted publishing on GitHub Release — see `RELEASING.md`.
  Keep `pyproject.toml` `version` and `__init__.py` `__version__` in lockstep.

## Roadmap (in priority order)

1. ~~Engine 2 — network TLS prober~~ — shipped in v0.2.0
   (`quantumshield/tls_probe.py`, `probe` CLI command). Verified against
   live targets: hybrid PQC (cloudflare.com, google.com, example.com all
   negotiate X25519MLKEM768) and legacy TLS (badssl.com TLS 1.0/1.1 hosts).
2. ~~AST-based detection for Python and JS~~ — shipped. Python via stdlib
   `ast` (`ast_detect.py`); JS via optional `esprima` (`js_detect.py`, `[js]`
   extra — kept optional to honour the stdlib-only-core convention). Import-
   alias resolution, key sizes / curve names from args, no comment/string
   false positives. TS/JSX not parsed (regex fallback). Also shipped a demo
   web UI (`webapp.py`, `[web]` extra, `serve` command).
3. Mosca-inequality migration urgency per asset (user supplies data shelf-life
   and migration time; flag where shelf-life + migration > CRQC estimate).
4. ~~Lockfile/dependency analysis~~ — shipped in v0.5.0 (`deps.py`). Prompted by
   dogfooding: scanning a real project reported a transitive
   `ecdsa-sig-formatter` as CRITICAL. Lockfiles are now parsed as dependency
   graphs with capped severity rather than regex-matched as code.
5. SaaS layer (multi-repo tracking, CBOM diffing over time) — design-partner
   validation FIRST, do not build speculatively.

## Owner context

- Owner: Pranay — senior cybersecurity engineer (detection engineering, IR,
  Microsoft Sentinel/KQL, MDR background), building a PQC portfolio/brand.
- Public artifacts matter: README quality, demo assets, and honest limitation
  notes are part of the product. Keep the tone credible, not salesy.
- Related repos to keep stylistically consistent: OT-PQC Scout, Q|Vault.
