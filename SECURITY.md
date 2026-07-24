# Security Policy

## Reporting a vulnerability

Please report security issues **privately** via
[GitHub Security Advisories](https://github.com/4p3Ir0n/quantumshield/security/advisories/new)
rather than opening a public issue.

I'll acknowledge within 72 hours and aim to have a fix released within 14 days
for anything exploitable. You'll get credit in the advisory unless you'd rather
not. This is a personal open-source project, not a funded product — there's no
bug bounty, just genuine thanks.

## Supported versions

Fixes land on the latest release only. QuantumShield is pre-1.0 and moves
quickly; please upgrade before reporting.

| Version | Supported |
|---|---|
| 0.5.x | Yes |
| < 0.5 | No |

## Threat model — what to expect from this tool

QuantumShield is a **read-only discovery tool**. Understanding what it does and
doesn't touch should make triage easier:

- **`scan` only reads.** It never modifies, uploads, or transmits the code it
  scans. All output is written to the directory you pass to `-o`.
- **Private keys are never parsed.** Key material is detected by PEM header
  only (`BEGIN RSA PRIVATE KEY`); the tool does not read, decode, or store the
  key itself. See `KEY_HEADERS` in `scanner.py`.
- **`probe` performs a standard TLS handshake** against hosts you name — it
  sends a ClientHello, reads the ServerHello, and disconnects. No credentials,
  no payloads, no exploitation, and it never completes a key exchange. It is
  equivalent in effect to `openssl s_client`. Only probe hosts you are
  authorised to test.
- **No telemetry.** The tool makes no network connections except the TLS
  handshakes you explicitly request via `probe`.

## The web UI (`quantumshield serve`)

This is the highest-risk component and deserves an explicit note.

`serve` is a **local demonstration surface**. It has **no authentication** and
returns file paths and source-line snippets from the filesystem. Two controls
are enforced in code:

1. **Path confinement.** Every requested path is resolved with
   `os.path.realpath` and must sit inside the server root (`--root`, default:
   the current directory). `..` traversal and symlinks pointing outside the
   root are rejected.
2. **Loopback-only by default.** Binding a non-loopback interface requires the
   explicit `--allow-remote` flag.

**Do not expose this to a network you don't control**, even with `--root` set.
If you need multi-user access, put it behind an authenticating reverse proxy —
the tool provides no authentication of its own and is not intended to.

## Handling scan output

Treat CBOM, SARIF and baseline files as **sensitive**. They are, by design, a
map of exactly where cryptography lives in your codebase, with file paths and
line numbers. Think before committing them to a public repository or attaching
them to a public issue.
