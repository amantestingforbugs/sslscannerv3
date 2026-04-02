"""
ssl_checker.py — Core SSL certificate checking logic.
Original script preserved as-is; wrapped for programmatic use.
"""

import ssl
import socket
import fnmatch
import ipaddress
import logging
import os
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from typing import List, Dict, Callable, Optional, Iterator

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import idna
    HAS_IDNA = True
except ImportError:
    HAS_IDNA = False

logger = logging.getLogger(__name__)

# ---- Errors that are expected/noisy and should be soft-classified ----
IGNORED_ERRORS = [
    "Timeout", "DNS failure", "TLS unrecognized name",
    "Connection reset by peer", "Connection refused",
    "Network unreachable", "Invalid hostname",
    "TLS internal error", "SSL handshake failure",
]


# ------------------- Helpers (original script logic) -------------------

def extract_hostname(url: str) -> str:
    try:
        parsed = urlparse(url.strip())
        return parsed.hostname or url.strip()
    except Exception:
        return url.strip()


def base_domain(hostname: str) -> str:
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        if HAS_TLDEXTRACT:
            ext = tldextract.extract(hostname)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
        parts = hostname.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def is_hostname_match(hostname: str, cert_names: List[str]) -> bool:
    if not cert_names:
        return False
    for name in cert_names:
        try:
            ipaddress.ip_address(hostname)
            if hostname == name:
                return True
        except ValueError:
            pattern = name.replace("*.", "*")
            if fnmatch.fnmatch(hostname.lower(), pattern.lower()):
                return True
    return False


def classify_error(e: Exception) -> str:
    msg = str(e)
    if "nodename nor servname provided" in msg or "Name or service not known" in msg:
        return "DNS failure"
    elif "timed out" in msg:
        return "Timeout"
    elif "TLSV1_UNRECOGNIZED_NAME" in msg:
        return "TLS unrecognized name"
    elif "TLSV1_ALERT_INTERNAL_ERROR" in msg:
        return "TLS internal error"
    elif "SSLV3_ALERT_HANDSHAKE_FAILURE" in msg:
        return "SSL handshake failure"
    elif "Label has disallowed hyphens" in msg:
        return "Invalid hostname"
    elif "Codepoint U+005F" in msg or "Empty Label" in msg:
        return "Invalid hostname"
    elif "No route to host" in msg:
        return "Network unreachable"
    elif "Connection reset by peer" in msg:
        return "Connection reset by peer"
    elif "Connection refused" in msg:
        return "Connection refused"
    else:
        return msg[:120]  # truncate long SSL error strings


# ------------------- Core check (original script logic) -------------------

def get_cert_info(hostname: str) -> Dict:
    """Check SSL certificate for a single hostname. Returns a result dict."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        host_idna = idna.encode(hostname).decode() if HAS_IDNA else hostname

        with socket.create_connection((host_idna, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host_idna) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

                if not HAS_CRYPTOGRAPHY:
                    return {"hostname": hostname, "error": "cryptography library not installed"}

                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                cn = ""
                try:
                    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    cn = cn_attr[0].value if cn_attr else ""
                except Exception:
                    pass

                sans = []
                try:
                    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    sans = list(ext.value.get_values_for_type(x509.DNSName))
                except Exception:
                    pass

                # Handle both naive and aware datetime objects
                raw_expiry = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
                now = datetime.now(timezone.utc) if (hasattr(raw_expiry, "tzinfo") and raw_expiry.tzinfo) else datetime.utcnow()
                days_left = (raw_expiry - now).days
                expiry_str = raw_expiry.strftime("%Y-%m-%d")

                issuer = cert.issuer.rfc4514_string()
                all_names = ([cn] if cn else []) + sans
                match_found = is_hostname_match(hostname, all_names)
                same_base = base_domain(hostname) == (base_domain(cn) if cn else "")

                return {
                    "hostname": hostname,
                    "cn": cn,
                    "sans": sans,
                    "issuer": issuer,
                    "expiry": expiry_str,
                    "days_left": days_left,
                    "match_found": match_found,
                    "same_base": same_base,
                    "error": None,
                    # Derived flags
                    "is_mismatch": not match_found,
                    "is_expired": days_left < 0,
                    "is_expiring_soon": 0 <= days_left <= 30,
                    "is_ok": match_found and days_left > 30,
                }
    except Exception as e:
        err = classify_error(e)
        return {
            "hostname": hostname,
            "error": err,
            "is_ignored_error": err in IGNORED_ERRORS,
        }


# ------------------- Batch runner -------------------

def _iter_hostnames(hostnames) -> Iterator[str]:
    for h in hostnames:
        if h:
            yield h


def run_checker(
    hostnames: List[str],
    max_workers: int = 50,
    progress_callback: Optional[Callable] = None,
    collect_results: bool = True,
    pause_event=None,
    stop_event=None,
) -> List[Dict]:
    """
    Run SSL checks concurrently against a list of hostnames.
    progress_callback(done, total, result) is called after each completed check.
    """
    # Keep worker count sane for very large host lists to avoid thread thrash.
    env_workers = int(os.getenv("SSL_MAX_WORKERS", str(max_workers or 50)))
    workers = max(1, min(env_workers, 256))
    total = len(hostnames)
    results = [] if collect_results else None

    host_iter = iter(_iter_hostnames(hostnames))
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        inflight = set()

        # Prime in-flight queue once; do NOT submit millions of futures at once.
        for _ in range(workers):
            try:
                inflight.add(executor.submit(get_cert_info, next(host_iter)))
            except StopIteration:
                break

        while inflight:
            if stop_event and stop_event.is_set():
                break
            while pause_event and pause_event.is_set():
                if stop_event and stop_event.is_set():
                    break
                try:
                    pause_event.wait(0.2)
                except Exception:
                    break
            if stop_event and stop_event.is_set():
                break
            finished, inflight = wait(inflight, return_when=FIRST_COMPLETED)
            for future in finished:
                if stop_event and stop_event.is_set():
                    break
                done += 1
                result = future.result()
                if collect_results:
                    results.append(result)
                if progress_callback:
                    try:
                        progress_callback(done, total, result)
                    except Exception:
                        pass
                try:
                    inflight.add(executor.submit(get_cert_info, next(host_iter)))
                except StopIteration:
                    pass
        if stop_event and stop_event.is_set():
            for future in inflight:
                future.cancel()

    return results or []


def parse_hosts_file(content: str) -> List[str]:
    """Parse a hosts file (text content) into a clean list of hostnames."""
    hosts: List[str] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        host = extract_hostname(line)
        if host:
            hosts.append(host)
    return hosts
