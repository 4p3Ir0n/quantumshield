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

    probe_p = sub.add_parser("probe", help="live TLS handshake probe of host:port targets")
    probe_p.add_argument("targets", nargs="+", help="one or more host:port targets to probe")
    probe_p.add_argument("-o", "--output", default="quantumshield-out",
                         help="output directory (default: quantumshield-out)")
    probe_p.add_argument("--json-only", action="store_true", help="emit CBOM only, skip HTML report")
    probe_p.add_argument("--timeout", type=float, default=5.0, help="per-target timeout in seconds")

    args = p.parse_args(argv)
    return _run_scan(args) if args.command == "scan" else _run_probe(args)


def _run_scan(args):
    if not os.path.isdir(args.path):
        print(f"error: {args.path} is not a directory", file=sys.stderr)
        return 2

    target = os.path.basename(os.path.abspath(args.path))
    print(f"QuantumShield v{__version__} — scanning {args.path} ...")
    scanner = Scanner(args.path)
    findings = scanner.scan()
    score = score_findings(findings)

    os.makedirs(args.output, exist_ok=True)
    cbom_path = os.path.join(args.output, "cbom.cdx.json")
    write_json(build_cbom(findings, target, score), cbom_path)
    print(f"  CBOM     -> {cbom_path}")
    if not args.json_only:
        report_path = os.path.join(args.output, "report.html")
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(render_report(findings, target, score,
                                   scanner.files_scanned, scanner.certs_parsed))
        print(f"  Report   -> {report_path}")

    print(f"\n  Files scanned: {scanner.files_scanned} | certificates parsed: {scanner.certs_parsed}")
    print(f"  Quantum readiness: {score['score']}/100 (grade {score['grade']})")
    for sev, n in score["counts"].items():
        if n:
            print(f"    {sev:<8} {n}")
    return 1 if score["counts"]["CRITICAL"] else 0


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


if __name__ == "__main__":
    raise SystemExit(main())
