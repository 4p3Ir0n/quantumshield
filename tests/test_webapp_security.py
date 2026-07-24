"""Security tests for the demo web UI.

Before v0.5.1 the UI accepted arbitrary absolute filesystem paths with no
authentication and returned source-line snippets, so anyone who bound it to a
reachable interface had an unauthenticated file-disclosure endpoint. These
tests pin the two controls that replaced the docstring warning.
"""

import os

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from quantumshield import webapp  # noqa: E402
from quantumshield.webapp import (  # noqa: E402
    PathNotAllowed, app, configure, is_local_host, resolve_path, serve,
)

client = TestClient(app)


@pytest.fixture
def rooted(tmp_path, monkeypatch):
    """Confine the app to a temp root containing one scannable project."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    secret = tmp_path.parent / "outside-secret"
    secret.mkdir(exist_ok=True)
    (secret / "keys.py").write_text("k = rsa.generate_private_key(65537)\n")
    old = webapp.current_root()
    configure(str(tmp_path))
    yield tmp_path, proj, secret
    configure(old)


# ------------------------------------------------------------- confinement
def test_path_inside_root_is_allowed(rooted):
    _, proj, _ = rooted
    assert resolve_path(str(proj)) == os.path.realpath(str(proj))


def test_absolute_path_outside_root_is_refused(rooted):
    _, _, secret = rooted
    with pytest.raises(PathNotAllowed):
        resolve_path(str(secret))


def test_dotdot_traversal_is_refused(rooted):
    _, proj, _ = rooted
    with pytest.raises(PathNotAllowed):
        resolve_path(str(proj / ".." / ".." / "outside-secret"))


def test_relative_traversal_is_refused(rooted):
    with pytest.raises(PathNotAllowed):
        resolve_path("../outside-secret")


def test_system_paths_are_refused(rooted):
    for p in ("/etc", "/", "C:\\Windows", os.path.expanduser("~")):
        with pytest.raises(PathNotAllowed):
            resolve_path(p)


def test_nonexistent_path_inside_root_is_refused(rooted):
    with pytest.raises(PathNotAllowed):
        resolve_path("no-such-dir")


def test_error_does_not_distinguish_missing_from_forbidden(rooted):
    """Same message either way, so the endpoint isn't an existence oracle."""
    _, _, secret = rooted
    try:
        resolve_path("definitely-not-here")
    except PathNotAllowed as a:
        missing = str(a)
    try:
        resolve_path(str(secret))
    except PathNotAllowed as b:
        forbidden = str(b)
    assert missing == forbidden


# ----------------------------------------------------------------- routes
def test_api_scan_refuses_path_outside_root(rooted):
    _, _, secret = rooted
    r = client.get("/api/scan", params={"path": str(secret)})
    assert r.status_code == 400
    assert "keys.py" not in r.text          # no content leaked

def test_report_refuses_path_outside_root(rooted):
    _, _, secret = rooted
    r = client.get("/report", params={"path": str(secret)})
    assert r.status_code == 400
    assert "rsa" not in r.text.lower()


def test_api_scan_still_works_inside_root(rooted):
    _, proj, _ = rooted
    r = client.get("/api/scan", params={"path": str(proj)})
    assert r.status_code == 200
    assert r.json()["cbom"]["specVersion"] == "1.6"


def test_index_reports_refusal_without_echoing_content(rooted):
    _, _, secret = rooted
    r = client.get("/", params={"path": str(secret), "go": "1"})
    assert r.status_code == 200
    assert "server root" in r.text
    assert "/report?path=" not in r.text     # no iframe wired up


# ------------------------------------------------------------ bind guard
@pytest.mark.parametrize("host,local", [
    ("127.0.0.1", True), ("localhost", True), ("::1", True), ("127.0.0.5", True),
    ("0.0.0.0", False), ("192.168.1.10", False), ("10.0.0.1", False),
])
def test_is_local_host(host, local):
    assert is_local_host(host) is local


def test_serve_refuses_non_loopback_without_flag(tmp_path):
    with pytest.raises(PermissionError, match="refusing to bind"):
        serve(host="0.0.0.0", port=0, root=str(tmp_path))


def test_serve_error_names_the_escape_hatch(tmp_path):
    try:
        serve(host="0.0.0.0", port=0, root=str(tmp_path))
    except PermissionError as exc:
        assert "--allow-remote" in str(exc)


def test_configure_defaults_to_cwd():
    old = webapp.current_root()
    try:
        assert configure(None) == os.path.realpath(os.getcwd())
    finally:
        configure(old)
