"""
Live TLS Scanner — DRD Section 7.1
===================================
Opens a TCP socket to host:443, performs a real TLS handshake via ssl.SSLContext,
extracts the peer certificate in DER form, and feeds it into the same
cert_scanner.scan_certificate() code path used for uploaded certificates.

No duplicate parsing logic — this module is purely an alternate *input source*.

NFR-3 compliance: genuine network failures (DNS, timeout, TLS handshake) raise
LiveScanError with a distinct error type so the API layer can return 503 with a
machine-readable detail string the frontend uses for its silent fallback UI.
"""

import json
import os
import ssl
import socket
import tempfile
import threading
import uuid
import re
import logging
from typing import List
from datetime import datetime, timezone

from models.schemas import Finding, SourceType, ContextType, UsageType, RiskLevel
from detection.cert_scanner import scan_certificate

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────
DEFAULT_PORT = 443
CONNECT_TIMEOUT_SECONDS = 8  # DRD target: < 10s total for the full live scan

# ── Cache path for NFR-3 offline fallback ─────────────────────────────
CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "exports")
CACHE_FILE = os.path.join(CACHE_DIR, "live_scan_cache.json")

# Serialises read-modify-write on the shared cache file. Without this,
# concurrent scans clobber each other and most results never persist.
_CACHE_LOCK = threading.Lock()


class LiveScanError(Exception):
    """Raised on genuine network/TLS failures so the API can return 503."""
    pass

class HostUnreachableError(LiveScanError):
    pass

class TimeoutScanError(LiveScanError):
    pass

class WeakCryptoRejectedError(LiveScanError):
    pass


class InvalidHostnameError(LiveScanError):
    """
    Raised when the input isn't a syntactically valid hostname at all.

    Distinct from LiveScanError so the API layer can answer 400 (caller sent
    bad input) instead of 503 (we tried and the network failed). Callers must
    NOT attempt the cached-fallback path for this — there is nothing to look
    up, and re-validating would just raise again.
    """
    pass


def _normalize_hostname(hostname: str) -> str:
    """Lowercase, strip protocol prefix, and drop any path/port suffix."""
    hostname = hostname.strip().lower()
    if hostname.startswith("https://"):
        hostname = hostname[8:]
    if hostname.startswith("http://"):
        hostname = hostname[7:]
    return hostname.split("/")[0].split(":")[0]


def _validate_hostname(hostname: str) -> str:
    """
    Basic hostname sanitization per DRD Section 9.
    Prevents shell-injection by rejecting anything that isn't a valid hostname.
    """
    original = hostname.strip()
    hostname = _normalize_hostname(hostname)

    pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
    )
    if not pattern.match(hostname):
        raise InvalidHostnameError(
            f"'{original}' is not a valid hostname. Enter a domain name such as "
            f"example.com (IP addresses, URLs with paths, and localhost are not supported)."
        )
    return hostname


def _fetch_certificate_chain(hostname: str, port: int = DEFAULT_PORT) -> tuple[list[bytes], str | None]:
    """
    Performs a real TLS handshake and returns the certificate chain as a list of bytes (DER or PEM encoded).
    This is the core I/O operation — everything else reuses cert_scanner.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # Load the system's default CA bundle
    ctx.load_default_certs()

    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT_SECONDS) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                try:
                    chain = [cert.public_bytes().encode('utf-8') for cert in tls_sock._sslobj.get_unverified_chain()]
                except AttributeError:
                    der_bytes = tls_sock.getpeercert(binary_form=True)
                    if not der_bytes:
                        raise LiveScanError(f"TLS handshake succeeded but no certificate returned for {hostname}")
                    chain = [der_bytes]
                return chain, None
    except socket.gaierror as e:
        raise HostUnreachableError(f"DNS resolution failed for {hostname}: {e}")
    except socket.timeout:
        raise TimeoutScanError(f"Connection timed out for {hostname}:{port}")
    except ConnectionRefusedError:
        raise HostUnreachableError(f"Connection refused by {hostname}:{port}")
    except ssl.SSLCertVerificationError as e:
        verify_error = str(e.verify_message) if hasattr(e, "verify_message") else str(e)
        insecure_ctx = ssl._create_unverified_context()
        try:
            with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT_SECONDS) as raw_sock:
                with insecure_ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                    try:
                        chain = [cert.public_bytes().encode('utf-8') for cert in tls_sock._sslobj.get_unverified_chain()]
                    except AttributeError:
                        der_bytes = tls_sock.getpeercert(binary_form=True)
                        if not der_bytes:
                            raise LiveScanError(f"TLS handshake succeeded but no certificate returned for {hostname}")
                        chain = [der_bytes]
                    return chain, verify_error
        except ssl.SSLError as insecure_e:
            err_str = str(insecure_e).lower()
            if any(x in err_str for x in ["dh key too small", "bad dh value", "unsupported protocol", "handshake failure", "no shared cipher"]):
                raise WeakCryptoRejectedError(f"TLS handshake failed (weak crypto): {insecure_e}")
            raise LiveScanError(f"TLS certificate verification failed ({verify_error}) and insecure fallback failed: {insecure_e}")
        except Exception as insecure_e:
            raise HostUnreachableError(f"TLS certificate verification failed ({verify_error}) and insecure fallback failed: {insecure_e}")
    except ssl.SSLError as e:
        err_str = str(e).lower()
        if any(x in err_str for x in ["dh key too small", "bad dh value", "unsupported protocol", "handshake failure", "no shared cipher"]):
            raise WeakCryptoRejectedError(f"TLS handshake failed (weak crypto): {e}")
        raise LiveScanError(f"TLS handshake failed for {hostname}: {e}")
    except OSError as e:
        raise HostUnreachableError(f"Network error connecting to {hostname}: {e}")


def extract_port(raw_hostname: str, default: int = DEFAULT_PORT) -> int:
    """
    Pulls an explicit :port off the input if the user supplied one.

    Previously any port was silently parsed off and discarded, so
    'example.com:8443' quietly probed 443 instead and reported on the wrong
    service. Honour it when it's a sane port number.
    """
    candidate = raw_hostname.strip().lower()
    if candidate.startswith("https://"):
        candidate = candidate[8:]
    if candidate.startswith("http://"):
        candidate = candidate[7:]
    candidate = candidate.split("/")[0]

    if ":" in candidate:
        maybe_port = candidate.rsplit(":", 1)[1]
        if maybe_port.isdigit():
            port = int(maybe_port)
            if 1 <= port <= 65535:
                return port
    return default


def scan_live_host(hostname: str, port: int = None) -> List[Finding]:
    """
    Full live-scan pipeline:
    1. Validate & sanitize hostname
    2. Perform real TLS handshake
    3. Feed the DER certificate into cert_scanner.scan_certificate()
    4. Cache the result for NFR-3 offline fallback
    5. Return the Finding(s)

    Raises InvalidHostnameError (bad input) or LiveScanError (network failure).
    """
    if port is None:
        port = extract_port(hostname)
    hostname = _validate_hostname(hostname)

    # ── Real TLS probe ────────────────────────────────────────────────
    try:
        chain_bytes_list, verify_err = _fetch_certificate_chain(hostname, port)
    except WeakCryptoRejectedError as wce:
        return [Finding(
            finding_id=f"f_{uuid.uuid4().hex[:8]}",
            source_type=SourceType.live_scan,
            file=f"live://{hostname}:{port} (Connection Refused)",
            hostname=hostname,
            algorithm="UNSUPPORTED/WEAK_CRYPTO",
            context=ContextType.production_cert,
            usage_type=UsageType.misc,
            risk_score=RiskLevel.Critical,
            description=f"Modern TLS libraries refuse to connect to this host because its cryptographic parameters are critically weak. This represents a maximum-severity legacy cryptography exposure. Details: {wce}"
        )]

    findings = []
    if verify_err:
        findings.append(Finding(
            finding_id=f"f_{uuid.uuid4().hex[:8]}",
            source_type=SourceType.live_scan,
            file=f"live://{hostname}:{port} (Config Error)",
            hostname=hostname,
            algorithm="TLS_VERIFY_ERROR",
            context=ContextType.production_cert,
            usage_type=UsageType.misc,
            risk_score=RiskLevel.Critical
        ))

    # ── Feed into the SAME cert_scanner code path — no duplicate logic ─
    for idx, cert_bytes in enumerate(chain_bytes_list):
        finding = scan_certificate(
            file_path=f"live://{hostname}:{port}",
            cert_bytes=cert_bytes,
            context=ContextType.production_cert,
        )
        finding.source_type = SourceType.live_scan
        finding.hostname = hostname
        finding.file = None  # Not a file — it's a live endpoint
        
        if idx == 0:
            finding.chain_position = "leaf"
            finding.is_actionable = True
        elif idx == len(chain_bytes_list) - 1:
            finding.chain_position = "root"
            finding.is_actionable = False
            finding.risk_score = RiskLevel.Low
        else:
            finding.chain_position = "intermediate"
            finding.is_actionable = False
            finding.risk_score = RiskLevel.Low

        findings.append(finding)

    # ── Cache for NFR-3 offline fallback ──────────────────────────────
    _cache_result(hostname, findings)

    return findings


def get_cached_result(hostname: str) -> List[Finding] | None:
    """
    Returns the last cached Finding list for a hostname, or None.
    Used by the API layer for NFR-3 fallback on genuine network failures.

    Deliberately does NOT re-validate the hostname: this is called from inside
    an exception handler, and raising a second error there is what previously
    turned a clean rejection into an unhandled 500.
    """
    hostname = _normalize_hostname(hostname)
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with _CACHE_LOCK:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                cache = json.load(f)
        entry = cache.get(hostname)
        if entry:
            return [Finding(**fd) for fd in entry["findings"]]
    except Exception as e:
        logger.warning("Could not read live scan cache for %s: %s", hostname, e)
    return None


def _cache_result(hostname: str, findings: List[Finding]) -> None:
    """
    Persists the latest successful scan result for offline fallback.

    The whole read-modify-write runs under a lock and lands via an atomic
    os.replace, so concurrent scans can't clobber each other's entries or
    leave a half-written file behind.
    """
    os.makedirs(CACHE_DIR, exist_ok=True)
    entry = {
        "cached_at": datetime.now(timezone.utc).isoformat(),
        "findings": [f.model_dump(mode="json") for f in findings],
    }

    with _CACHE_LOCK:
        cache = {}
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    cache = json.load(f)
            except Exception:
                cache = {}

        cache[hostname] = entry

        tmp_fd, tmp_path = tempfile.mkstemp(dir=CACHE_DIR, suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
            os.replace(tmp_path, CACHE_FILE)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
