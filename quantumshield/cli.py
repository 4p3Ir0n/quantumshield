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
    p.add_argument("command", choices=["scan"])
    p.add_argument("path", help="directory to scan")
    p.add_argument("-o", "--output", default="quantumshield-out",
                   help="output directory (default: quantumshield-out)")
    p.add_argument("--json-only", action="store_true", help="emit CBOM only, skip HTML report")
    p.add_argument("--version", action="version", version=f"QuantumShield {__version__}")
    args = p.parse_args(argv)

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


if __name__ == "__main__":
    raise SystemExit(main())
