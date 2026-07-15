"""Keyless passive subdomain enumeration sources.

The helpers in this module are intentionally independent of the Flask routes and
Subfinder runner so merge conflicts in those integration files stay small.
"""

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

PASSIVE_SOURCE_TIMEOUT = max(5, int(os.getenv("SUBDOMAIN_PASSIVE_SOURCE_TIMEOUT", "20")))
_HOST_RE = re.compile(r"^(?:\*\.)?(?=.{1,253}$)(?!-)[a-z0-9-]+(?:\.[a-z0-9-]+)+$", re.IGNORECASE)


def normalize_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    if "://" in h:
        try:
            parsed = urlparse(h)
            if parsed.hostname:
                h = parsed.hostname
            else:
                h = h.split("://", 1)[1].split("/", 1)[0]
        except Exception:
            h = h.split("://", 1)[1].split("/", 1)[0]
    if h.startswith("*."):
        h = h[2:]
    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]
    elif ":" in h:
        h = h.split(":", 1)[0]
    return h


def is_host_within_root(host: str, root_domain: str) -> bool:
    return host == root_domain or host.endswith(f".{root_domain}")


def candidate_hosts_from_text(text: str, root_domain: str) -> Set[str]:
    """Extract in-scope hostnames from arbitrary source output."""
    if not text:
        return set()
    escaped_root = re.escape(root_domain)
    host_pattern = re.compile(rf"(?:\*\.)?(?:[a-z0-9-]+\.)+{escaped_root}", re.IGNORECASE)
    hosts: Set[str] = set()
    for match in host_pattern.finditer(text):
        host = normalize_host(match.group(0))
        if host and _HOST_RE.match(host) and is_host_within_root(host, root_domain):
            hosts.add(host)
    return hosts


def extract_hosts_from_json(payload: object, root_domain: str) -> Set[str]:
    """Recursively extract in-scope hostnames from JSON API responses."""
    hosts: Set[str] = set()
    if isinstance(payload, dict):
        for value in payload.values():
            hosts.update(extract_hosts_from_json(value, root_domain))
    elif isinstance(payload, list):
        for item in payload:
            hosts.update(extract_hosts_from_json(item, root_domain))
    elif isinstance(payload, str):
        hosts.update(candidate_hosts_from_text(payload, root_domain))
    return hosts


def fetch_passive_url(url: str, timeout: int) -> Tuple[str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "ssl-sentinel-subdomain-enumerator/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        content_type = resp.headers.get("content-type", "")
        body = resp.read(5_000_000).decode("utf-8", errors="replace")
    return content_type, body


def passive_source_urls(root_domain: str) -> Dict[str, str]:
    quoted = urllib.parse.quote(root_domain, safe="")
    return {
        "crt.sh": f"https://crt.sh/?q=%25.{quoted}&output=json",
        "Cert Spotter": f"https://api.certspotter.com/v1/issuances?domain={quoted}&include_subdomains=true&expand=dns_names",
        "HackerTarget": f"https://api.hackertarget.com/hostsearch/?q={quoted}",
        "RapidDNS": f"https://rapiddns.io/subdomain/{quoted}?full=1",
        "AlienVault OTX": f"https://otx.alienvault.com/api/v1/indicators/domain/{quoted}/passive_dns",
        "urlscan.io": f"https://urlscan.io/api/v1/search/?q=domain:{quoted}",
        "ThreatMiner": f"https://api.threatminer.org/v2/domain.php?q={quoted}&rt=5",
        "BufferOver DNS": f"https://dns.bufferover.run/dns?q=.{quoted}",
        "Anubis": f"https://jldc.me/anubis/subdomains/{quoted}",
        "Wayback Machine": f"https://web.archive.org/cdx?url=*.{quoted}/*&output=json&fl=original&collapse=urlkey",
    }


def query_passive_source(source: str, url: str, root_domain: str, timeout: int) -> Tuple[str, List[str], Optional[str]]:
    try:
        content_type, body = fetch_passive_url(url, timeout)
        hosts: Set[str] = set()
        if "json" in content_type.lower() or body.lstrip().startswith(("{", "[")):
            try:
                hosts.update(extract_hosts_from_json(json.loads(body), root_domain))
            except json.JSONDecodeError:
                hosts.update(candidate_hosts_from_text(body, root_domain))
        else:
            hosts.update(candidate_hosts_from_text(body, root_domain))
        return source, sorted(hosts), None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return source, [], str(exc)[:500]


def enumerate_passive_subdomains(root_domain: str, timeout: int = PASSIVE_SOURCE_TIMEOUT) -> Dict[str, object]:
    """Query built-in passive sources and return in-scope subdomains.

    Slow or rate-limited sources are reported as warnings in the returned
    ``errors`` mapping and do not fail the overall enumeration.
    """
    found_by_source: Dict[str, List[str]] = {}
    errors: Dict[str, str] = {}
    sources = passive_source_urls(root_domain)
    workers = max(1, min(8, len(sources)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(query_passive_source, source, url, root_domain, timeout): source
            for source, url in sources.items()
        }
        for future in as_completed(futures):
            source, hosts, error = future.result()
            found_by_source[source] = hosts
            if error:
                errors[source] = error
    for source in sources:
        found_by_source.setdefault(source, [])
    all_hosts = sorted({host for hosts in found_by_source.values() for host in hosts})
    return {"root_domain": root_domain, "found": all_hosts, "sources": found_by_source, "errors": errors}
