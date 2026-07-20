"""QuantumShield — discovery engine 2: network TLS prober.

Given host:port targets, performs a live TLS handshake to determine the
negotiated protocol version and cipher suite (via the stdlib `ssl` module),
then crafts a raw TLS 1.3 ClientHello advertising PQC-hybrid key-exchange
groups to determine the negotiated key-share group — the stdlib `ssl` module
has no public API to read the negotiated group, so that part is done by hand.

Findings flow through the same CBOM/scoring/report pipeline as the
filesystem scanner, tagged asset_type="protocol".

Known limitation: negotiated-group detection only works against TLS 1.3
servers, since group selection for TLS 1.2 and earlier happens in the
ServerKeyExchange message rather than a ServerHello extension, which this
module doesn't parse.
"""

from __future__ import annotations

import os
import random
import socket
import ssl
import struct
from dataclasses import dataclass

from .patterns import ALGORITHMS, WEAK_PROTOCOLS, SEVERITIES
from .scanner import Finding, Occurrence

# ---------------------------------------------------------------- registry
# TLS 1.3 SupportedGroups we actively probe for (IANA TLS SupportedGroups
# registry). 0x11EC (4588) is X25519MLKEM768, the hybrid PQC group.
GROUPS = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1",
    29: "x25519", 30: "x448",
    256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096",
    0x11EC: "X25519MLKEM768",
}
HYBRID_PQC_GROUPS = {0x11EC}

# groups we offer key_share entries for, in preference order
OFFERED_GROUPS = [0x11EC, 29, 23, 24]

_CIPHER_SUITES = bytes.fromhex("130113021303")  # AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305
_SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0807]
_KEY_SHARE_LEN = {23: 65, 24: 97, 25: 133, 29: 32, 30: 56, 0x11EC: 1216}

DEFAULT_TIMEOUT = 5.0


@dataclass
class ProbeResult:
    target: str
    reachable: bool
    protocol: str | None = None
    cipher: str | None = None
    group: str | None = None
    hybrid_pqc: bool = False
    error: str | None = None


# ------------------------------------------------------------- networking
def _default_connect(host: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


def _do_ssl_handshake(host: str, port: int, timeout: float,
                      connect=_default_connect) -> tuple[str, str]:
    """Real handshake via the stdlib `ssl` module. Returns (protocol, cipher_name).

    We deliberately negotiate down to whatever the server supports, down to
    SSLv3 — a probe that refuses to complete a handshake with a legacy
    server can't report that the server is legacy. `check_hostname`/
    `verify_mode` are disabled for the same reason: we're fingerprinting the
    live handshake, not validating a certificate chain.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.SSLv3
    except (ValueError, AttributeError):
        ctx.minimum_version = ssl.TLSVersion.TLSv1  # SSLv3 unsupported by this OpenSSL build
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    raw = connect(host, port, timeout)
    with ctx.wrap_socket(raw, server_hostname=host) as tls:
        return tls.version(), tls.cipher()[0]


def _probe_group(host: str, port: int, timeout: float,
                 connect=_default_connect) -> int | None:
    """Craft a raw TLS 1.3 ClientHello and read back the negotiated group
    from the ServerHello's (or HelloRetryRequest's) key_share extension."""
    sock = connect(host, port, timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(_build_client_hello(host, OFFERED_GROUPS))
        handshake_msg = _read_server_hello(sock)
        return _parse_negotiated_group(handshake_msg)
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ------------------------------------------------------- ClientHello build
def _u16(n: int) -> bytes:
    return struct.pack("!H", n)


def _u24(n: int) -> bytes:
    return struct.pack("!I", n)[1:]


def _ext(ext_type: int, data: bytes) -> bytes:
    return _u16(ext_type) + _u16(len(data)) + data


# ML-KEM-768 has k=3 degree-256 polynomials; FIPS 203's ByteEncode_12 packs
# each 256-coefficient polynomial into 384 bytes (12 bits/coefficient).
_MLKEM768_Q = 3329
_MLKEM768_K = 3


def _byte_encode_12(coeffs: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(coeffs), 2):
        d0, d1 = coeffs[i], coeffs[i + 1]
        out.append(d0 & 0xFF)
        out.append(((d0 >> 8) & 0x0F) | ((d1 & 0x0F) << 4))
        out.append((d1 >> 4) & 0xFF)
    return bytes(out)


def _fake_mlkem768_encapsulation_key() -> bytes:
    """A structurally well-formed (every coefficient < q, correctly packed)
    but cryptographically meaningless ML-KEM-768 encapsulation key.

    We never complete a real key exchange — the connection is torn down
    right after reading the ServerHello — so the key doesn't need to be a
    real keypair. But several TLS stacks apply FIPS 203's modulus check to
    the encoding on receipt and reject anything that fails it with a
    decode_error alert before ever sending a ServerHello, so pure random
    bytes don't work here; only the coefficient encoding needs to be valid.
    """
    t_hat = b"".join(
        _byte_encode_12([random.randrange(_MLKEM768_Q) for _ in range(256)])
        for _ in range(_MLKEM768_K)
    )
    rho = os.urandom(32)
    return t_hat + rho


def _key_share_data(group: int) -> bytes:
    if group == 0x11EC:
        return _fake_mlkem768_encapsulation_key() + os.urandom(32)  # ML-KEM768 pk || X25519 pk
    return os.urandom(_KEY_SHARE_LEN[group])


def _build_client_hello(host: str, groups: list[int]) -> bytes:
    random_bytes = os.urandom(32)
    session_id = os.urandom(32)

    sni_name = host.encode("ascii")
    sni_entry = b"\x00" + _u16(len(sni_name)) + sni_name  # name_type=host_name
    ext_sni = _ext(0x0000, _u16(len(sni_entry)) + sni_entry)
    ext_versions = _ext(0x002b, bytes([2]) + _u16(0x0304))  # supported_versions: TLS 1.3
    ext_groups = _ext(0x000a, _u16(len(groups) * 2) + b"".join(_u16(g) for g in groups))
    ext_sigalgs = _ext(0x000d, _u16(len(_SIG_ALGS) * 2) + b"".join(_u16(s) for s in _SIG_ALGS))

    key_share_entries = []
    for g in groups:
        if g not in _KEY_SHARE_LEN:
            continue
        data = _key_share_data(g)
        key_share_entries.append(_u16(g) + _u16(len(data)) + data)
    key_shares = b"".join(key_share_entries)
    ext_keyshare = _ext(0x0033, _u16(len(key_shares)) + key_shares)

    extensions = ext_sni + ext_versions + ext_groups + ext_sigalgs + ext_keyshare

    body = (
        b"\x03\x03" + random_bytes +                       # legacy_version, random
        bytes([len(session_id)]) + session_id +             # legacy_session_id
        _u16(len(_CIPHER_SUITES)) + _CIPHER_SUITES +
        b"\x01\x00" +                                        # compression methods: [null]
        _u16(len(extensions)) + extensions
    )
    handshake = b"\x01" + _u24(len(body)) + body            # handshake type 1 = ClientHello
    record = b"\x16\x03\x01" + _u16(len(handshake)) + handshake  # record type 22 = handshake
    return record


# --------------------------------------------------------- response parse
_ALERT_DESCRIPTIONS = {40: "handshake_failure", 70: "protocol_version",
                       80: "internal_error", 112: "unrecognized_name"}


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed while reading TLS record")
        buf += chunk
    return buf


def _recv_tls_record(sock) -> tuple[int, bytes]:
    header = _recv_exact(sock, 5)
    content_type = header[0]
    length = struct.unpack("!H", header[3:5])[0]
    return content_type, _recv_exact(sock, length)


def _read_server_hello(sock) -> bytes:
    """Read handshake records until a full ServerHello/HelloRetryRequest
    handshake message has been assembled (it may span several TLS records)."""
    buf = b""
    needed = None
    while needed is None or len(buf) < needed:
        content_type, payload = _recv_tls_record(sock)
        if content_type == 0x15:  # alert
            level, desc = payload[0], payload[1]
            raise ConnectionError(
                f"TLS alert during handshake: level={level} "
                f"description={_ALERT_DESCRIPTIONS.get(desc, desc)}")
        if content_type != 0x16:  # handshake
            raise ConnectionError(f"unexpected TLS record type {content_type}")
        buf += payload
        if needed is None and len(buf) >= 4:
            needed = 4 + int.from_bytes(buf[1:4], "big")
    return buf[:needed]


def _parse_negotiated_group(handshake_msg: bytes) -> int | None:
    """Extract the NamedGroup from a ServerHello/HelloRetryRequest's key_share
    extension. Both message shapes start the extension body with the 2-byte
    group id, so no special-casing is needed between them."""
    if len(handshake_msg) < 4 or handshake_msg[0] != 0x02:  # 2 = server_hello
        return None
    body = handshake_msg[4:]
    pos = 2 + 32  # legacy_version + random
    if pos >= len(body):
        return None
    session_id_len = body[pos]
    pos += 1 + session_id_len
    pos += 2 + 1  # cipher_suite + legacy_compression_method
    if pos + 2 > len(body):
        return None
    ext_total_len = struct.unpack("!H", body[pos:pos + 2])[0]
    pos += 2
    ext_end = pos + ext_total_len
    while pos + 4 <= ext_end and pos + 4 <= len(body):
        ext_type = struct.unpack("!H", body[pos:pos + 2])[0]
        ext_len = struct.unpack("!H", body[pos + 2:pos + 4])[0]
        ext_data = body[pos + 4:pos + 4 + ext_len]
        if ext_type == 0x0033 and len(ext_data) >= 2:  # key_share
            return struct.unpack("!H", ext_data[:2])[0]
        pos += 4 + ext_len
    return None


# --------------------------------------------------------------- probing
def probe_target(target: str, timeout: float = DEFAULT_TIMEOUT, *,
                 ssl_handshake=None, group_probe=None) -> ProbeResult:
    ssl_handshake = ssl_handshake or _do_ssl_handshake
    group_probe = group_probe or _probe_group

    host, _, port_s = target.rpartition(":")
    if not host or not port_s.isdigit():
        return ProbeResult(target=target, reachable=False,
                           error="expected target in 'host:port' form")
    port = int(port_s)

    try:
        protocol, cipher = ssl_handshake(host, port, timeout)
    except Exception as exc:  # noqa: BLE001 - surface any handshake failure as unreachable
        return ProbeResult(target=target, reachable=False, error=str(exc))

    group_id = None
    if protocol == "TLSv1.3":
        try:
            group_id = group_probe(host, port, timeout)
        except Exception:  # noqa: BLE001 - group detection is best-effort
            group_id = None

    if group_id is None:
        group_name = None
    else:
        group_name = GROUPS.get(group_id, f"unknown(0x{group_id:04x})")

    return ProbeResult(
        target=target, reachable=True, protocol=protocol, cipher=cipher,
        group=group_name, hybrid_pqc=bool(group_id) and group_id in HYBRID_PQC_GROUPS,
    )


def probe_targets(targets: list[str], timeout: float = DEFAULT_TIMEOUT) -> list[ProbeResult]:
    return [probe_target(t, timeout) for t in targets]


# ------------------------------------------------------------ to findings
def results_to_findings(results: list[ProbeResult]) -> list[Finding]:
    findings: dict[str, Finding] = {}

    def add(key: str, kwargs: dict, occ: Occurrence):
        f = findings.get(key)
        if f is None:
            f = Finding(**kwargs)
            findings[key] = f
        f.occurrences.append(occ)

    for r in results:
        if not r.reachable:
            continue

        weak_sev = WEAK_PROTOCOLS.get(r.protocol)
        if weak_sev:
            add(f"proto:{r.protocol}",
                dict(algorithm=r.protocol, asset_type="protocol", severity=weak_sev,
                     nist_qsl=0, primitive="protocol",
                     note=f"{r.protocol} is deprecated. Configure TLS 1.2 minimum and plan "
                          f"TLS 1.3 with hybrid PQC key exchange (X25519MLKEM768)."),
                Occurrence(r.target, 0, r.cipher or "", "live TLS handshake: legacy protocol negotiated"))

        if r.group and not r.group.startswith("unknown"):
            if r.hybrid_pqc:
                meta = ALGORITHMS["ML-KEM"]
                add(f"group:{r.group}",
                    dict(algorithm=f"{r.group} (hybrid PQC key exchange)", asset_type="protocol",
                         severity=meta["severity"], nist_qsl=meta["nist_qsl"],
                         primitive=meta["primitive"], note=meta["note"], oid=meta.get("oid")),
                    Occurrence(r.target, 0, r.protocol or "", "live TLS handshake: hybrid PQC group negotiated"))
            else:
                algo_key = "DH" if r.group.startswith("ffdhe") else "ECDH"
                meta = ALGORITHMS[algo_key]
                add(f"group:{r.group}",
                    dict(algorithm=f"{r.group} (TLS key exchange)", asset_type="protocol",
                         severity=meta["severity"], nist_qsl=meta["nist_qsl"],
                         primitive=meta["primitive"], note=meta["note"], oid=meta.get("oid")),
                    Occurrence(r.target, 0, r.protocol or "", "live TLS handshake: classical key-exchange group negotiated"))

    return sorted(findings.values(), key=lambda f: (SEVERITIES.index(f.severity), f.algorithm))
