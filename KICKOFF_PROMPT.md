# One-paste kickoff prompt for Claude Code

Unzip quantumshield-repo.zip somewhere (e.g. ~/projects/quantumshield), open a
terminal in that folder, run `claude`, and paste the prompt below. That's it —
CLAUDE.md carries all remaining context, so you never need to re-explain.

---

Read CLAUDE.md for full project context. Then, working autonomously and
verifying each step before moving on:

1. VERIFY: create a venv, `pip install -e ".[dev]"`, run `pytest` — all 16
   tests must pass. Run `quantumshield scan examples/vulnerable-demo -o /tmp/qs`
   and confirm exit code 1, a valid CycloneDX 1.6 CBOM, and the HTML report.
2. PUBLISH: initialise git, create a sensible first commit, then create a
   public GitHub repo named `quantumshield` using `gh repo create` (ask me to
   run `gh auth login` only if needed) and push. Confirm the CI workflow runs
   green on GitHub Actions.
3. DOGFOOD: run quantumshield against my other local project folders (ask me
   for paths). For any false positives or missed detections, fix patterns.py
   WITH accompanying tests (positive + false-positive guard, per CLAUDE.md
   conventions), commit, and push.
4. BUILD ENGINE 2: implement the network TLS prober exactly as specified in
   the CLAUDE.md roadmap item 1 — new `probe` command, hybrid PQC group
   detection, findings flowing through the existing CBOM/scoring/report
   pipeline, full test coverage (mock sockets where needed), README section,
   version bump to 0.2.0, commit and push.
5. REPORT: when done, summarise what changed, test counts, and anything that
   needs my judgement.

Work step by step; don't skip verification. If a step fails, diagnose and fix
it yourself before asking me.
