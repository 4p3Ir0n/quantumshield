"""QuantumShield — demo web UI.

A thin FastAPI wrapper around the scanner so the tool can be demonstrated in a
browser: point it at a repo path, it runs a real scan and renders the same
CBOM/score/report the CLI produces. Optional dependency:
`pip install "quantumshield[web]"`.

**This is a local demonstration surface, not a multi-tenant service.** It reads
the filesystem and returns source-line snippets, so two controls are enforced
rather than merely documented:

* Every requested path is confined to a **root** (default: the working
  directory). Paths outside it are refused, and resolution happens through
  `os.path.realpath` so `..` traversal and symlinks out of the root are caught.
* It binds to **127.0.0.1** and refuses any other interface unless started
  with `--allow-remote`, because exposing an unauthenticated endpoint that
  reads arbitrary files is a bad afternoon for whoever does it.

Run with `quantumshield serve` (or `uvicorn quantumshield.webapp:app`).
"""

from __future__ import annotations

import html
import os

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse

from . import __version__
from .scanner import Scanner
from .cbom import build_cbom, score_findings
from .report import render_report

app = FastAPI(title="QuantumShield", version=__version__)

# Scans are confined to this directory. Set via configure(); defaults to cwd so
# importing the app directly (e.g. `uvicorn quantumshield.webapp:app`) is still
# confined rather than wide open.
_ROOT = os.path.realpath(os.getcwd())


class PathNotAllowed(Exception):
    """A requested path is outside the configured root, or isn't a directory."""


def configure(root: str | None = None) -> str:
    """Set the directory scans are confined to. Returns the resolved root."""
    global _ROOT
    _ROOT = os.path.realpath(root or os.getcwd())
    return _ROOT


def current_root() -> str:
    return _ROOT


def resolve_path(path: str) -> str:
    """Resolve a user-supplied path and confine it to the root.

    A single error for both "outside the root" and "not a directory" keeps the
    endpoint from doubling as an existence oracle for paths it won't serve.
    """
    root = os.path.realpath(_ROOT)
    raw = path or "."
    candidate = raw if os.path.isabs(raw) else os.path.join(root, raw)
    target = os.path.realpath(candidate)
    try:
        inside = os.path.commonpath([root, target]) == root
    except ValueError:
        inside = False          # different drives on Windows
    if not inside or not os.path.isdir(target):
        raise PathNotAllowed(
            f"path must be an existing directory inside the server root ({root})")
    return target


def _demo_path() -> str:
    """Bundled vulnerable-demo fixture, but only if it's inside the root."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidate = os.path.join(repo_root, "examples", "vulnerable-demo")
    if not os.path.isdir(candidate):
        return ""
    try:
        return resolve_path(candidate)
    except PathNotAllowed:
        return ""


def _run_scan(path: str):
    scanner = Scanner(path)
    findings = scanner.scan()
    score = score_findings(findings)
    target = os.path.basename(os.path.abspath(path))
    cbom = build_cbom(findings, target, score)
    return scanner, findings, score, target, cbom


# ---------------------------------------------------------------- landing UI
_LANDING_CSS = """
:root{--ink:#0E1726;--bg:#F4F7FA;--panel:#FFFFFF;--line:#DDE5EC;--violet:#5B4BD4;
--mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--ink);font:15px/1.6 'Inter',-apple-system,'Segoe UI',sans-serif;min-height:100vh}
header{background:var(--panel);border-bottom:1px solid var(--line);padding:18px 0}
.wrap{max-width:1080px;margin:0 auto;padding:0 28px}
.brand{font-family:'Sora','Inter',sans-serif;font-weight:700;font-size:19px;letter-spacing:-.02em}
.brand span{color:var(--violet)}
.tagline{color:#5A6B7E;font-size:13.5px;margin-top:2px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:24px 26px;margin-top:26px}
h2{font-family:'Sora',sans-serif;font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.14em;color:#42526A;margin-bottom:14px}
form{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
input[type=text]{flex:1;min-width:280px;font-family:var(--mono);font-size:13.5px;padding:12px 14px;
border:1px solid var(--line);border-radius:8px;background:#FBFCFE;color:var(--ink)}
input[type=text]:focus{outline:none;border-color:var(--violet);box-shadow:0 0 0 3px rgba(91,75,212,.12)}
button{font-family:'Sora',sans-serif;font-weight:600;font-size:14px;color:#fff;background:var(--violet);
border:none;border-radius:8px;padding:12px 24px;cursor:pointer}
button:hover{background:#4a3cc0}
.chips{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}
.chip{font-family:var(--mono);font-size:12px;color:var(--violet);background:rgba(91,75,212,.08);
border:1px solid rgba(91,75,212,.2);border-radius:20px;padding:5px 13px;cursor:pointer;text-decoration:none}
.chip:hover{background:rgba(91,75,212,.15)}
.err{color:#B3362B;font-family:var(--mono);font-size:13px;margin-top:14px}
.frame-wrap{margin-top:26px}
iframe{width:100%;height:1400px;border:1px solid var(--line);border-radius:12px;background:var(--panel)}
.meta{font-family:var(--mono);font-size:11.5px;color:#8295A8;margin-top:24px}
footer{padding:30px 0}
"""


def _landing(path_value: str, error: str = "", show_report_for: str = "") -> str:
    demo = _demo_path()
    chips = ""
    if demo:
        chips = (f'<div class="chips"><a class="chip" '
                 f'href="/?path={html.escape(demo, quote=True)}&go=1">▶ scan bundled vulnerable-demo</a></div>')
    err_html = f'<div class="err">⚠ {html.escape(error)}</div>' if error else ""
    frame = ""
    if show_report_for:
        src = "/report?path=" + html.escape(show_report_for, quote=True)
        frame = f'<div class="frame-wrap"><iframe src="{src}" title="scan report"></iframe></div>'

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuantumShield — crypto discovery</title>
<style>{_LANDING_CSS}</style></head><body>
<header><div class="wrap">
  <div class="brand">Quantum<span>Shield</span></div>
  <div class="tagline">Post-quantum cryptography discovery — scan a codebase, get a CBOM + quantum readiness score</div>
</div></header>
<div class="wrap">
  <div class="panel">
    <h2>Scan a directory</h2>
    <form action="/" method="get">
      <input type="text" name="path" placeholder="/absolute/path/to/repo"
             value="{html.escape(path_value, quote=True)}" autofocus>
      <input type="hidden" name="go" value="1">
      <button type="submit">Scan</button>
    </form>
    {chips}
    {err_html}
  </div>
  {frame}
  <div class="meta">QuantumShield v{__version__} · results below are a live scan of the path above ·
  API: <code>/api/scan?path=…</code> returns the raw CycloneDX 1.6 CBOM</div>
</div>
<footer></footer>
</body></html>"""


# ------------------------------------------------------------------ routes
@app.get("/", response_class=HTMLResponse)
def index(path: str = "", go: str = ""):
    if not path:
        return _landing(_demo_path())
    if not go:
        return _landing(path)
    try:
        resolve_path(path)
    except PathNotAllowed as exc:
        return _landing(path, error=str(exc))
    return _landing(path, show_report_for=path)


@app.get("/report", response_class=HTMLResponse)
def report(path: str = Query(...)):
    try:
        safe = resolve_path(path)
    except PathNotAllowed as exc:
        return HTMLResponse(f"<p>{html.escape(str(exc))}</p>", status_code=400)
    scanner, findings, score, target, _ = _run_scan(safe)
    return render_report(findings, target, score, scanner.files_scanned, scanner.certs_parsed)


@app.get("/api/scan")
def api_scan(path: str = Query(...)):
    try:
        safe = resolve_path(path)
    except PathNotAllowed as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    scanner, findings, score, target, cbom = _run_scan(safe)
    return JSONResponse({
        "target": target,
        "score": score,
        "files_scanned": scanner.files_scanned,
        "certificates_parsed": scanner.certs_parsed,
        "cbom": cbom,
    })


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": __version__}


LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "127.0.0.0/8"}


def is_local_host(host: str) -> bool:
    return host in LOCAL_HOSTS or host.startswith("127.")


def serve(host: str = "127.0.0.1", port: int = 8000, root: str | None = None,
          allow_remote: bool = False):
    """Launch the demo server (used by the `quantumshield serve` CLI command).

    Refuses to bind a non-loopback interface unless `allow_remote` is set:
    this endpoint reads the filesystem and returns source snippets, and it has
    no authentication, so binding it to 0.0.0.0 by accident should not be one
    keystroke away.
    """
    import uvicorn

    resolved_root = configure(root)
    if not is_local_host(host) and not allow_remote:
        raise PermissionError(
            f"refusing to bind {host}: the web UI is unauthenticated and reads "
            f"files under {resolved_root}. Re-run with --allow-remote if you "
            f"really intend to expose it.")
    uvicorn.run(app, host=host, port=port)
