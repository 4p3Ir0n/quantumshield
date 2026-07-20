"""Tests for the demo web UI (quantumshield.webapp).

FastAPI is an optional dependency; tests skip cleanly if it's absent.
"""

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from quantumshield.webapp import app  # noqa: E402

client = TestClient(app)

DEMO = "examples/vulnerable-demo"


def test_landing_page_renders():
    r = client.get("/")
    assert r.status_code == 200
    assert "QuantumShield" in r.text
    assert "Scan a directory" in r.text


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_report_on_demo_dir():
    r = client.get("/report", params={"path": DEMO})
    assert r.status_code == 200
    # rendered report includes the score card and at least one CRITICAL finding
    assert "quantum readiness" in r.text.lower()
    assert "CRITICAL" in r.text


def test_report_rejects_non_directory():
    r = client.get("/report", params={"path": "does-not-exist-xyz"})
    assert r.status_code == 400


def test_api_scan_returns_cbom():
    r = client.get("/api/scan", params={"path": DEMO})
    assert r.status_code == 200
    body = r.json()
    assert body["cbom"]["bomFormat"] == "CycloneDX"
    assert body["cbom"]["specVersion"] == "1.6"
    assert body["score"]["counts"]["CRITICAL"] >= 1
    assert body["files_scanned"] > 0


def test_api_scan_rejects_non_directory():
    r = client.get("/api/scan", params={"path": "nope-not-here"})
    assert r.status_code == 400


def test_index_with_go_embeds_report_iframe():
    r = client.get("/", params={"path": DEMO, "go": "1"})
    assert r.status_code == 200
    assert "/report?path=" in r.text  # iframe wired to the report route


def test_index_with_bad_path_shows_error():
    r = client.get("/", params={"path": "not-a-real-dir", "go": "1"})
    assert r.status_code == 200
    assert "Not a directory" in r.text
