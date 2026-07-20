"""Tests for quantumshield.tls_probe — Engine 2, the network TLS prober.

Real TLS handshakes aren't exercised over the network here (that would be
flaky and needs live infrastructure). Instead:
  * the hand-rolled TLS record/handshake parsing is tested against
    hand-crafted byte fixtures via a FakeSocket,
  * probe_target() is tested with injected ssl_handshake/group_probe
    callables, and
  * one CLI test hits a definitely-closed local port to verify the
    "unreachable target" path end-to-end without any real network dependency.
"""

import json
import os
import socket
import subprocess
import sys

import pytest

from quantumshield.tls_probe import (
    ProbeResult, _build_client_hello, _ext, _parse_negotiated_group,
    _probe_group, _read_server_hello, _u16, _u24, probe_target, probe_targets,
    results_to_findings,
)


# --------------------------------------------------------------- fixtures
class FakeSocket:
    """Serves pre-baked bytes from .recv(), optionally capped per call to
    force fragmentation across multiple reads. Captures .sendall() input."""

    def __init__(self, data: bytes, chunk_size: int | None = None):
        self._data = data
        self._pos = 0
        self._chunk_size = chunk_size
        self.sent = b""

    def settimeout(self, timeout):
        pass

    def sendall(self, data: bytes):
        self.sent += data

    def recv(self, n: int) -> bytes:
        limit = n if self._chunk_size is None else min(n, self._chunk_size)
        chunk = self._data[self._pos:self._pos + limit]
        self._pos += len(chunk)
        return chunk

    def close(self):
        pass


def _wrap_record(payload: bytes, content_type: int = 0x16) -> bytes:
    return bytes([content_type]) + b"\x03\x03" + _u16(len(payload)) + payload


def _make_server_hello(group_id: int, key_exchange_len: int = 32,
                       keyshare_body: bytes | None = None) -> bytes:
    """Build a minimal, well-formed ServerHello handshake message advertising
    the given group in its key_share extension."""
    random_bytes = b"\x00" * 32
    cipher_suite = b"\x13\x01"
    ext_versions = _ext(0x002b, b"\x03\x04")
    if keyshare_body is None:
        keyshare_body = _u16(group_id) + _u16(key_exchange_len) + os.urandom(key_exchange_len)
    ext_keyshare = _ext(0x0033, keyshare_body)
    extensions = ext_versions + ext_keyshare
    body = (b"\x03\x03" + random_bytes + b"\x00" + cipher_suite + b"\x00" +
           _u16(len(extensions)) + extensions)
    return b"\x02" + _u24(len(body)) + body


# ------------------------------------------------------- ClientHello build
def test_build_client_hello_offers_hybrid_pqc_group():
    record = _build_client_hello("example.com", [0x11EC, 29])
    assert record[:3] == b"\x16\x03\x01"          # record: handshake, legacy version
    assert record[5] == 0x01                       # handshake type: ClientHello
    assert b"\x11\xec" in record                   # X25519MLKEM768 group id offered
    assert b"example.com" in record                # SNI


# --------------------------------------------------------- response parse
def test_parse_negotiated_group_classical():
    msg = _make_server_hello(29)  # x25519
    assert _parse_negotiated_group(msg) == 29


def test_parse_negotiated_group_hybrid_pqc():
    msg = _make_server_hello(0x11EC, key_exchange_len=1216)
    assert _parse_negotiated_group(msg) == 0x11EC


def test_parse_negotiated_group_hello_retry_request_shape():
    # KeyShareHelloRetryRequest is just the 2-byte NamedGroup, no key data.
    msg = _make_server_hello(0x11EC, keyshare_body=_u16(0x11EC))
    assert _parse_negotiated_group(msg) == 0x11EC


def test_parse_negotiated_group_no_key_share_extension():
    ext_versions = _ext(0x002b, b"\x03\x04")
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x13\x01" + b"\x00" + _u16(len(ext_versions)) + ext_versions
    msg = b"\x02" + _u24(len(body)) + body
    assert _parse_negotiated_group(msg) is None


def test_parse_negotiated_group_wrong_message_type():
    assert _parse_negotiated_group(b"\x0b\x00\x00\x02\x00\x00") is None  # 0x0b = Certificate


def test_read_server_hello_single_record():
    msg = _make_server_hello(29)
    sock = FakeSocket(_wrap_record(msg))
    assert _read_server_hello(sock) == msg


def test_read_server_hello_fragmented_reads():
    # Force many tiny recv() calls to exercise the reassembly loop.
    msg = _make_server_hello(0x11EC, key_exchange_len=1216)
    sock = FakeSocket(_wrap_record(msg), chunk_size=3)
    assert _read_server_hello(sock) == msg


def test_read_server_hello_split_across_two_records():
    msg = _make_server_hello(29)
    half = len(msg) // 2
    data = _wrap_record(msg[:half]) + _wrap_record(msg[half:])
    sock = FakeSocket(data)
    assert _read_server_hello(sock) == msg


def test_read_server_hello_alert_raises():
    alert = _wrap_record(bytes([2, 40]), content_type=0x15)  # fatal, handshake_failure
    sock = FakeSocket(alert)
    with pytest.raises(ConnectionError, match="handshake_failure"):
        _read_server_hello(sock)


def test_probe_group_end_to_end_with_fake_socket():
    msg = _make_server_hello(0x11EC, key_exchange_len=1216)
    fake = FakeSocket(_wrap_record(msg))
    group_id = _probe_group("example.com", 443, 5.0, connect=lambda h, p, t: fake)
    assert group_id == 0x11EC
    assert fake.sent[:1] == b"\x16"       # our crafted ClientHello record
    assert fake.sent[5] == 0x01           # handshake type: ClientHello


# --------------------------------------------------------------- probing
def test_probe_target_hybrid_pqc():
    r = probe_target(
        "pqc.example.com:443",
        ssl_handshake=lambda h, p, t: ("TLSv1.3", "TLS_AES_256_GCM_SHA384"),
        group_probe=lambda h, p, t: 0x11EC,
    )
    assert r.reachable and r.protocol == "TLSv1.3"
    assert r.group == "X25519MLKEM768" and r.hybrid_pqc is True


def test_probe_target_classical_group():
    r = probe_target(
        "classic.example.com:443",
        ssl_handshake=lambda h, p, t: ("TLSv1.3", "TLS_AES_128_GCM_SHA256"),
        group_probe=lambda h, p, t: 29,
    )
    assert r.group == "x25519" and r.hybrid_pqc is False


def test_probe_target_tls12_skips_group_probe():
    def _fail_if_called(h, p, t):
        raise AssertionError("group_probe must not run for a TLS 1.2 handshake")

    r = probe_target(
        "legacy.example.com:443",
        ssl_handshake=lambda h, p, t: ("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256"),
        group_probe=_fail_if_called,
    )
    assert r.reachable and r.protocol == "TLSv1.2" and r.group is None


def test_probe_target_unreachable():
    def _refuse(h, p, t):
        raise ConnectionRefusedError("connection refused")

    r = probe_target("down.example.com:443", ssl_handshake=_refuse)
    assert r.reachable is False and "refused" in r.error


def test_probe_target_rejects_malformed_target():
    r = probe_target("no-port-here")
    assert r.reachable is False and "host:port" in r.error


def test_probe_targets_runs_all(monkeypatch):
    import quantumshield.tls_probe as tls_probe
    monkeypatch.setattr(tls_probe, "_do_ssl_handshake",
                        lambda h, p, t, connect=None: ("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256"))
    results = probe_targets(["a.example.com:443", "b.example.com:443"])
    assert len(results) == 2 and all(r.reachable for r in results)


# ------------------------------------------------------------ to findings
def test_results_to_findings_weak_protocol():
    r = ProbeResult(target="a:443", reachable=True, protocol="TLSv1.1", cipher="X")
    f = results_to_findings([r])
    assert len(f) == 1
    assert f[0].algorithm == "TLSv1.1" and f[0].severity == "HIGH" and f[0].asset_type == "protocol"


def test_results_to_findings_hybrid_pqc_is_safe():
    r = ProbeResult(target="a:443", reachable=True, protocol="TLSv1.3", cipher="X",
                    group="X25519MLKEM768", hybrid_pqc=True)
    f = results_to_findings([r])
    assert len(f) == 1 and f[0].severity == "SAFE"


def test_results_to_findings_classical_group_is_critical():
    r = ProbeResult(target="a:443", reachable=True, protocol="TLSv1.3", cipher="X",
                    group="x25519", hybrid_pqc=False)
    f = results_to_findings([r])
    assert len(f) == 1 and f[0].severity == "CRITICAL"


def test_results_to_findings_ffdhe_group_maps_to_dh():
    r = ProbeResult(target="a:443", reachable=True, protocol="TLSv1.3", cipher="X",
                    group="ffdhe2048", hybrid_pqc=False)
    f = results_to_findings([r])
    assert len(f) == 1 and f[0].severity == "CRITICAL" and "ffdhe2048" in f[0].algorithm


def test_results_to_findings_skips_unreachable():
    r = ProbeResult(target="a:443", reachable=False, error="refused")
    assert results_to_findings([r]) == []


# -------------------------------------------------------------------- CLI
def test_cli_probe_unreachable_target_exits_clean(tmp_path):
    # Bind to get a free local port, then close it so the port is definitely
    # refusing connections — deterministic, no real network dependency.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    r = subprocess.run(
        [sys.executable, "-m", "quantumshield", "probe", f"127.0.0.1:{port}",
         "-o", str(tmp_path / "out"), "--json-only", "--timeout", "1"],
        capture_output=True, text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    assert r.returncode == 0
    bom = json.load(open(tmp_path / "out" / "cbom.cdx.json"))
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
