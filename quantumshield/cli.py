"""QuantumShield CLI."""
import argparse
import os
import sys

from . import __version__
from .scanner import Scanner
from .cbom import build_cbom, score_findings, write_json
from .report import render_report


def main(argv=None):
    p = argparse.ArgumentParser(prog="quantumshield",
                                description="Quantum-vulnerability crypto discovery scanner")
    p.add_argument("--version", action="version", version=f"QuantumShield {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a directory for cryptographic usage")
    scan_p.add_argument("path", help="directory to scan")
    scan_p.add_argument("-o", "--output", default="quantumshield-out",
                        help="output directory (default: quantumshield-out)")
    scan_p.add_argument("--json-only", action="store_true", help="emit CBOM only, skip HTML report")
    scan_p.add_argument("--sarif", action="store_true",
                        help="also emit results.sarif (SARIF 2.1.0) for code-scanning dashboards")
    scan_p.add_argument("--baseline", metavar="FILE",
                        help="report only findings absent from this baseline file")
    scan_p.add_argument("--write-baseline", metavar="FILE",
                        help="write current findings to a baseline file and exit 0")
    scan_p.add_argument("--fail-on", default="critical",
                        choices=["critical", "high", "medium", "low", "any", "never"],
                        help="minimum severity that makes the run exit 1 (default: critical)")

    probe_p = sub.add_parser("probe", help="live TLS handshake probe of host:port targets")
    probe_p.add_argument("targets", nargs="+", help="one or more host:port targets to probe")
    probe_p.add_argument("-o", "--output", default="quantumshield-out",
                         help="output directory (default: quantumshield-out)")
    probe_p.add_argument("--json-only", action="store_true", help="emit CBOM only, skip HTML report")
    probe_p.add_argument("--timeout", type=float, default=5.0, help="per-target timeout in seconds")

    serve_p = sub.add_parser("serve", help="launch the demo web UI (needs quantumshield[web])")
    serve_p.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    serve_p.add_argument("--port", type=int, default=8000, help="bind port (default: 8000)")
    serve_p.add_argument("--root", default=None,
                         help="confine scans to this directory (default: current directory)")
    serve_p.add_argument("--allow-remote", action="store_true",
                         help="permit binding a non-loopback interface (unauthenticated — "
                              "the UI reads files and returns source snippets)")

    args = p.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "probe":
        return _run_probe(args)
    return _run_serve(args)


FAIL_ON_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _should_fail(counts: dict, fail_on: str) -> bool:
    """True if any finding is at or above the configured severity floor."""
    if fail_on == "never":
        return False
    if fail_on == "any":
        return any(counts.get(s, 0) for s in FAIL_ON_ORDER)
    floor = FAIL_ON_ORDER.index(fail_on.upper())
    return any(counts.get(s, 0) for s in FAIL_ON_ORDER[:floor + 1])


def _run_scan(args):
    from .suppress import (load_baseline, apply_baseline, write_baseline,
                           self_artifact_patterns)

    if not os.path.isdir(args.path):
        print(f"error: {args.path} is not a directory", file=sys.stderr)
        return 2

    target = os.path.basename(os.path.abspath(args.path))
    print(f"QuantumShield v{__version__} — scanning {args.path} ...")
    scanner = Scanner(args.path)
    # Never scan our own output or baseline files if they sit inside the tree.
    for pattern in self_artifact_patterns(args.path, args.output, args.baseline,
                                          args.write_baseline):
        scanner.ignore.add(pattern)
    findings = scanner.scan()

    # Writing a baseline is a bookkeeping run: record today's findings and stop
    # without gating, so a team can adopt the CI gate before fixing the backlog.
    if args.write_baseline:
        n = write_baseline(findings, args.write_baseline, __version__)
        print(f"  Baseline -> {args.write_baseline} ({n} occurrences recorded)")
        return 0

    baselined = 0
    if args.baseline:
        try:
            known = load_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"error: could not read baseline: {exc}", file=sys.stderr)
            return 2
        findings, baselined = apply_baseline(findings, known)

    score = score_findings(findings)

    os.makedirs(args.output, exist_ok=True)
    cbom_path = os.path.join(args.output, "cbom.cdx.json")
    write_json(build_cbom(findings, target, score), cbom_path)
    print(f"  CBOM     -> {cbom_path}")
    if args.sarif:
        from .sarif import write_sarif
        sarif_path = os.path.join(args.output, "results.sarif")
        write_sarif(findings, sarif_path, target)
        print(f"  SARIF    -> {sarif_path}")
    if not args.json_only:
        report_path = os.path.join(args.output, "report.html")
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(render_report(findings, target, score,
                                   scanner.files_scanned, scanner.certs_parsed))
        print(f"  Report   -> {report_path}")

    print(f"\n  Files scanned: {scanner.files_scanned} | certificates parsed: {scanner.certs_parsed}")
    quiet = []
    if scanner.files_ignored or scanner.dirs_ignored:
        parts = []
        if scanner.dirs_ignored:
            parts.append(f"{scanner.dirs_ignored} dirs")
        if scanner.files_ignored:
            parts.append(f"{scanner.files_ignored} files")
        quiet.append(f"{' + '.join(parts)} ignored")
    if scanner.suppressed_inline:
        quiet.append(f"{scanner.suppressed_inline} inline-suppressed")
    if baselined:
        quiet.append(f"{baselined} baselined")
    if quiet:
        print(f"  Suppressed: {' | '.join(quiet)}")
    label = " (new findings only)" if args.baseline else ""
    print(f"  Quantum readiness: {score['score']}/100 (grade {score['grade']}){label}")
    for sev, n in score["counts"].items():
        if n:
            print(f"    {sev:<8} {n}")
    return 1 if _should_fail(score["counts"], args.fail_on) else 0


def _run_probe(args):
    from .tls_probe import probe_targets, results_to_findings

    print(f"QuantumShield v{__version__} — probing {len(args.targets)} target(s) ...")
    results = probe_targets(args.targets, timeout=args.timeout)
    findings = results_to_findings(results)
    score = score_findings(findings)

    target_label = args.targets[0] if len(args.targets) == 1 else f"{len(args.targets)} targets"
    reachable = sum(1 for r in results if r.reachable)

    os.makedirs(args.output, exist_ok=True)
    cbom_path = os.path.join(args.output, "cbom.cdx.json")
    write_json(build_cbom(findings, target_label, score), cbom_path)
    print(f"  CBOM     -> {cbom_path}")
    if not args.json_only:
        report_path = os.path.join(args.output, "report.html")
        with open(report_path, "w", encoding="utf-8") as fh:
            stats_text = f"{len(results)} targets probed &middot; {reachable} reachable"
            fh.write(render_report(findings, target_label, score, len(results), reachable,
                                   stats_text=stats_text))
        print(f"  Report   -> {report_path}")

    print(f"\n  Targets probed: {len(results)} | reachable: {reachable}")
    print(f"  Quantum readiness: {score['score']}/100 (grade {score['grade']})")
    for sev, n in score["counts"].items():
        if n:
            print(f"    {sev:<8} {n}")
    for r in results:
        if r.reachable:
            print(f"    {r.target:<28} {r.protocol} | {r.cipher} | group={r.group or 'unknown (TLS<1.3)'}")
        else:
            print(f"    {r.target:<28} UNREACHABLE ({r.error})")
    return 1 if score["counts"]["CRITICAL"] else 0


def _run_serve(args):
    try:
        from .webapp import serve
    except ImportError:
        print("error: the web UI needs extra dependencies. Install with:\n"
              "  pip install \"quantumshield[web]\"", file=sys.stderr)
        return 2
    root = os.path.realpath(args.root or os.getcwd())
    if not os.path.isdir(root):
        print(f"error: --root {root} is not a directory", file=sys.stderr)
        return 2
    print(f"QuantumShield v{__version__} — serving demo UI at http://{args.host}:{args.port}")
    print(f"  scans confined to: {root}")
    if args.allow_remote:
        print("  WARNING: --allow-remote is set. This UI has no authentication and\n"
              "           returns source-line snippets from files under the root.",
              file=sys.stderr)
    try:
        serve(host=args.host, port=args.port, root=root, allow_remote=args.allow_remote)
    except PermissionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
