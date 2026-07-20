"""QuantumShield — self-contained HTML report."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from . import __version__
from .scanner import Finding

SEV_COLORS = {"CRITICAL": "#B3362B", "HIGH": "#C7691A", "MEDIUM": "#B89015",
              "LOW": "#5A7A8C", "SAFE": "#2E7D5B"}
SEV_LABELS = {"CRITICAL": "Shor-breakable", "HIGH": "Broken / deprecated",
              "MEDIUM": "Grover-reduced", "LOW": "Monitor", "SAFE": "Quantum-ready"}

CSS = """
:root{--ink:#0E1726;--bg:#F4F7FA;--panel:#FFFFFF;--line:#DDE5EC;--violet:#5B4BD4;
--mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;}
*{box-sizing:border-box;margin:0}
body{background:var(--bg);color:var(--ink);font:15px/1.6 'Inter',-apple-system,'Segoe UI',sans-serif;padding:0 0 64px}
.wrap{max-width:1080px;margin:0 auto;padding:0 28px}
header{border-bottom:1px solid var(--line);background:var(--panel);padding:22px 0;margin-bottom:36px}
header .wrap{display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px}
.brand{font-family:'Sora','Inter',sans-serif;font-weight:700;font-size:19px;letter-spacing:-.02em}
.brand span{color:var(--violet)}
.meta{font-family:var(--mono);font-size:12px;color:#5A6B7E}
.scorecard{display:flex;gap:36px;align-items:center;background:var(--panel);border:1px solid var(--line);
border-radius:10px;padding:30px 34px;flex-wrap:wrap}
.score-num{font-family:'Sora',sans-serif;font-size:76px;font-weight:700;line-height:1;letter-spacing:-.04em}
.score-sub{font-family:var(--mono);font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:#5A6B7E;margin-top:6px}
.grade{font-family:'Sora',sans-serif;font-size:30px;font-weight:700;border:2px solid currentColor;border-radius:8px;
width:54px;height:54px;display:flex;align-items:center;justify-content:center}
.headline{flex:1;min-width:240px;font-size:16px}
.counts{display:flex;gap:18px;font-family:var(--mono);font-size:12px;flex-wrap:wrap}
.counts b{font-size:20px;display:block;font-family:'Sora',sans-serif}
h2{font-family:'Sora',sans-serif;font-size:15px;font-weight:600;text-transform:uppercase;letter-spacing:.14em;
color:#42526A;margin:42px 0 14px}
.spectrum{display:flex;height:46px;border-radius:8px;overflow:hidden;border:1px solid var(--line)}
.spectrum div{display:flex;align-items:center;justify-content:center;color:#fff;
font-family:var(--mono);font-size:12px;min-width:34px}
.legend{display:flex;gap:20px;margin-top:10px;font-family:var(--mono);font-size:11.5px;color:#5A6B7E;flex-wrap:wrap}
.dot{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px;vertical-align:baseline}
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--sev);
border-radius:8px;padding:18px 22px;margin-bottom:14px}
.frow{display:flex;justify-content:space-between;align-items:baseline;gap:14px;flex-wrap:wrap}
.fname{font-family:'Sora',sans-serif;font-weight:600;font-size:17px}
.badge{font-family:var(--mono);font-size:11px;letter-spacing:.08em;color:#fff;background:var(--sev);
border-radius:4px;padding:3px 9px}
.fnote{margin:8px 0 4px;color:#33415A;max-width:74ch}
.fdetail{font-family:var(--mono);font-size:12px;color:#5A6B7E;margin-top:4px}
details{margin-top:10px}
summary{font-family:var(--mono);font-size:12.5px;color:var(--violet);cursor:pointer}
.occ{font-family:var(--mono);font-size:12.5px;border-top:1px dashed var(--line);padding:7px 0;display:flex;gap:16px}
.occ .loc{color:var(--violet);white-space:nowrap}
.occ .code{color:#42526A;overflow-wrap:anywhere}
footer{margin-top:48px;font-family:var(--mono);font-size:11.5px;color:#8295A8}
@media (prefers-reduced-motion:no-preference){.scorecard{animation:rise .5s ease-out}
@keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1}}}
"""


def render_report(findings: list[Finding], target: str, score: dict,
                  files_scanned: int, certs_parsed: int, stats_text: str | None = None) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    grade_color = SEV_COLORS["SAFE"] if score["grade"] in "AB" else (
        SEV_COLORS["MEDIUM"] if score["grade"] == "C" else SEV_COLORS["CRITICAL"])

    stats_text = stats_text or f"{files_scanned} files scanned &middot; {certs_parsed} certificates parsed"
    counts = score["counts"]
    total = max(sum(counts.values()), 1)
    spectrum, legend = [], []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]:
        n = counts[sev]
        legend.append(f'<span><i class="dot" style="background:{SEV_COLORS[sev]}"></i>'
                      f'{SEV_LABELS[sev]} &middot; {n}</span>')
        if n:
            spectrum.append(f'<div style="background:{SEV_COLORS[sev]};flex:{n / total:.3f}" '
                            f'title="{sev}: {n}">{n}</div>')
    spectrum_html = "".join(spectrum) or '<div style="background:#2E7D5B;flex:1">no crypto assets found</div>'

    blocks = []
    for f in findings:
        occs = "".join(
            f'<div class="occ"><span class="loc">{html.escape(o.path)}:{o.line}</span>'
            f'<span class="code">{html.escape(o.snippet)}</span></div>'
            for o in f.occurrences[:25])
        more = (f'<div class="occ"><span class="code">&hellip; {len(f.occurrences) - 25} further '
                f'occurrences (see CBOM)</span></div>' if len(f.occurrences) > 25 else "")
        detail = f'<div class="fdetail">{html.escape(f.detail)}</div>' if f.detail else ""
        blocks.append(f"""
<div class="finding" style="--sev:{SEV_COLORS[f.severity]}">
  <div class="frow"><span class="fname">{html.escape(f.algorithm)}</span>
  <span class="badge">{f.severity} &middot; {SEV_LABELS[f.severity]}</span></div>
  {detail}
  <p class="fnote">{html.escape(f.note)}</p>
  <details><summary>{len(f.occurrences)} occurrence{'s' if len(f.occurrences) != 1 else ''}</summary>
  {occs}{more}</details>
</div>""")

    counts_html = "".join(
        f'<span style="color:{SEV_COLORS[s]}"><b>{counts[s]}</b>{s.lower()}</span>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QuantumShield report — {html.escape(target)}</title>
<style>{CSS}</style></head><body>
<header><div class="wrap">
  <span class="brand">Quantum<span>Shield</span> &middot; crypto discovery report</span>
  <span class="meta">target: {html.escape(target)} &middot; {ts} &middot; v{__version__}</span>
</div></header>
<div class="wrap">
  <div class="scorecard">
    <div><div class="score-num">{score['score']}</div>
         <div class="score-sub">quantum readiness / 100</div></div>
    <div class="grade" style="color:{grade_color}">{score['grade']}</div>
    <div class="headline">{score['headline']}<br>
      <span class="meta">{stats_text}</span></div>
    <div class="counts">{counts_html}</div>
  </div>
  <h2>Exposure spectrum</h2>
  <div class="spectrum">{spectrum_html}</div>
  <div class="legend">{''.join(legend)}</div>
  <h2>Findings</h2>
  {''.join(blocks) or '<p>No cryptographic assets detected.</p>'}
  <footer>Generated by QuantumShield v{__version__}. CBOM emitted alongside this report in
  CycloneDX 1.6 format. Severity model: Shor-breakable public-key crypto is rated CRITICAL
  due to harvest-now-decrypt-later exposure; classically broken primitives HIGH;
  Grover-reduced margins MEDIUM/LOW.</footer>
</div></body></html>"""
