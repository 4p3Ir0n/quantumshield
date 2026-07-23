# Releasing QuantumShield to PyPI

QuantumShield publishes to PyPI as **`quantumshield-pqc`** (the `quantumshield`
name is taken by an unrelated project). The import package and CLI stay
`quantumshield` — users run `pip install quantumshield-pqc` and then
`import quantumshield` / `quantumshield scan …`.

Publishing is automated via [`.github/workflows/publish.yml`](.github/workflows/publish.yml),
which uses **PyPI Trusted Publishing (OIDC)** — no API tokens or repository
secrets are stored anywhere.

## One-time setup (do this once, on PyPI)

Because the project doesn't exist on PyPI yet, register a *pending* trusted
publisher:

1. Sign in at <https://pypi.org> (create the account if needed).
2. Go to **Your account → Publishing → Add a pending publisher**.
3. Fill in exactly:
   - **PyPI Project Name:** `quantumshield-pqc`
   - **Owner:** `4p3Ir0n`
   - **Repository name:** `quantumshield`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `pypi`
4. Save. PyPI will now trust releases published by this repo's workflow and
   create the project on first upload.

(Optional but recommended: on GitHub, create an **Environment** named `pypi`
under Settings → Environments and add a required reviewer, so a human approves
each publish.)

## Cutting a release

> **Note:** v0.4.0 is published; the next release is v0.5.0. For that one, bump
> the version first (step 1), then continue.

1. Bump the version in **two** places (they must match):
   - `pyproject.toml` → `version`
   - `quantumshield/__init__.py` → `__version__`
2. Update `README.md` / `CLAUDE.md` if the change warrants it, commit, and push.
3. Tag and create a GitHub Release:
   ```bash
   git tag v0.5.0
   git push origin v0.5.0
   gh release create v0.5.0 --title "v0.5.0" --notes "…release notes…"
   ```
4. Publishing the release triggers `publish.yml`, which builds the sdist +
   wheel, runs `twine check`, and uploads to PyPI via OIDC.
5. Confirm at <https://pypi.org/project/quantumshield-pqc/> and verify a clean
   install:
   ```bash
   pip install quantumshield-pqc
   quantumshield --version
   ```

## Building / checking locally (no upload)

```bash
python -m pip install build twine
python -m build            # -> dist/quantumshield_pqc-<ver>.tar.gz + .whl
python -m twine check dist/*
```

To smoke-test the built wheel in an isolated environment before releasing:

```bash
python -m venv /tmp/qs-pkgtest
/tmp/qs-pkgtest/bin/pip install "dist/quantumshield_pqc-<ver>-py3-none-any.whl[js]"
/tmp/qs-pkgtest/bin/quantumshield --version
```

## Notes

- **First release:** the pending publisher (above) must exist before the first
  workflow run, or the upload step will fail authentication.
- **TestPyPI (optional):** to rehearse, add a second trusted publisher on
  <https://test.pypi.org> and a workflow step with
  `repository-url: https://test.pypi.org/legacy/`.
- The bundled `examples/vulnerable-demo` fixture is **not** shipped in the
  wheel, so `quantumshield scan examples/vulnerable-demo` and the web UI's
  "scan bundled demo" shortcut only work from a source checkout, not a
  `pip install`. Point the tool at your own path instead.
