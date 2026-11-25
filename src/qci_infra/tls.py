"""External TLS probe from the Mac Studio: which certificate a hostname really serves on 443.

Read-only: a TLS handshake with SNI, then the connection is closed (no HTTP request is sent).
"""

import hashlib
import ipaddress
import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone

import certifi


def resolve(host: str) -> list[str]:
    """IP addresses of `host`; raises OSError (socket.gaierror) when it does not resolve."""
    return sorted({a[4][0] for a in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})


def is_public(addrs: list[str]) -> bool:
    return any(ipaddress.ip_address(a).is_global for a in addrs)


def _handshake(host: str, port: int, timeout: float, verify: bool) -> tuple[bytes, dict]:
    ctx = ssl.create_default_context(cafile=certifi.where())
    if not verify:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        return t.getpeercert(binary_form=True), t.getpeercert()


def _decode(der: bytes) -> dict:
    """Decode an unverified certificate with the stdlib (getpeercert() is empty without verification)."""
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        return ssl._ssl._test_decode_cert(path)
    finally:
        os.unlink(path)


def served_cert(host: str, port: int = 443, timeout: float = 10) -> dict:
    """{thumb, not_after (ISO UTC), names, issuer, error}: `error` is the chain/hostname
    verification failure, or None when the certificate verifies for `host`.
    Raises OSError when no TLS handshake is possible."""
    try:
        der, info = _handshake(host, port, timeout, verify=True)
        error = None
    except ssl.SSLCertVerificationError as e:
        error = e.verify_message or str(e)
        # Second handshake only to read the (untrusted) certificate for the report; no data is sent.
        der, _ = _handshake(host, port, timeout, verify=False)
        info = _decode(der)
    issuer = dict(x[0] for x in info.get("issuer", ()))
    end = datetime.fromtimestamp(ssl.cert_time_to_seconds(info["notAfter"]), timezone.utc)
    return {"thumb": hashlib.sha1(der).hexdigest().upper(), "not_after": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "names": [v for k, v in info.get("subjectAltName", ()) if k == "DNS"],
            "issuer": issuer.get("commonName") or issuer.get("organizationName"), "error": error}
