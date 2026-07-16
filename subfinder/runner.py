"""
subfinder/runner.py
Integrates ProjectDiscovery Subfinder with the SSL Sentinel pipeline.

How it works:
  1. Extracts root domains from project hosts and runs subfinder per root
  2. Parses stdout for discovered subdomains
  3. Deduplicates against previously stored hosts
  4. New hosts are written to subfinder_hosts table
  5. New hosts are immediately queued for SSL scanning
  6. Reports an error if the subfinder binary is not available
"""

import gzip
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import threading
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from core.observability import log_event

log = logging.getLogger(__name__)

SUBFINDER_BIN = shutil.which("subfinder") or "/usr/local/bin/subfinder"
_sf_lock = threading.Lock()
_sf_state = {}  # project_id -> {status, job_id, new_count, root_domains, phase, progress}
_subfinder_all_flag_supported: Optional[bool] = None
MAX_CONCURRENT_SUBFINDER_PROJECTS = max(1, int(os.getenv("SUBFINDER_MAX_CONCURRENT_PROJECTS", "1")))
ACTIVE_SUBFINDER_STATUSES = {"queued", "extracting_roots", "running", "ssl_scanning"}

PASSIVE_SOURCE_TIMEOUT = max(2, int(os.getenv("SUBDOMAIN_PASSIVE_SOURCE_TIMEOUT", "12")))
MAX_ENUM_PROVIDER_WORKERS = max(1, int(os.getenv("SUBDOMAIN_ENUM_PROVIDER_WORKERS", "12")))
_ENUM_USER_AGENT = os.getenv("SUBDOMAIN_ENUM_USER_AGENT", "ssl-sentinel-subdomain-enumerator/1.0")


def _candidate_hosts_from_text(text: str, root_domain: str) -> Set[str]:
    """Extract in-scope hostnames from arbitrary source output."""
    if not text:
        return set()
    escaped_root = re.escape(root_domain)
    host_pattern = re.compile(rf"(?:\*\.)?(?:[a-z0-9-]+\.)+{escaped_root}", re.IGNORECASE)
    hosts: Set[str] = set()
    for match in host_pattern.finditer(text):
        host = _normalize_host(match.group(0))
        if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain):
            hosts.add(host)
    return hosts


def _extract_hosts_from_json(payload: object, root_domain: str) -> Set[str]:
    """Recursively extract in-scope hostnames from JSON API responses."""
    hosts: Set[str] = set()
    if isinstance(payload, dict):
        for value in payload.values():
            hosts.update(_extract_hosts_from_json(value, root_domain))
    elif isinstance(payload, list):
        for item in payload:
            hosts.update(_extract_hosts_from_json(item, root_domain))
    elif isinstance(payload, str):
        hosts.update(_candidate_hosts_from_text(payload, root_domain))
    return hosts


def _fetch_passive_url(url: str, timeout: int, headers: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
    request_headers = {"User-Agent": _ENUM_USER_AGENT}
    if headers:
        request_headers.update(headers)
    req = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        content_type = resp.headers.get("content-type", "")
        body = resp.read(5_000_000).decode("utf-8", errors="replace")
    return content_type, body



ProviderFetcher = Callable[[str, int], Set[str]]


class EnumerationProvider:
    """Small provider wrapper so new subdomain sources can be added declaratively."""

    def __init__(
        self,
        name: str,
        category: str,
        fetcher: ProviderFetcher,
        api_key_env: Optional[str] = None,
        report_errors: bool = True,
    ):
        self.name = name
        self.category = category
        self.fetcher = fetcher
        self.api_key_env = api_key_env
        self.report_errors = report_errors

    def enabled(self) -> bool:
        return not self.api_key_env or bool(os.getenv(self.api_key_env))

    def run(self, root_domain: str, timeout: int) -> Set[str]:
        if not self.enabled():
            return set()
        return self.fetcher(root_domain, timeout)


def _json_or_text_url_fetcher(url_template: str, headers_factory: Optional[Callable[[], Dict[str, str]]] = None) -> ProviderFetcher:
    def fetch(root_domain: str, timeout: int) -> Set[str]:
        quoted = urllib.parse.quote(root_domain, safe="")
        content_type, body = _fetch_passive_url(url_template.format(domain=quoted, raw_domain=root_domain), timeout, headers_factory() if headers_factory else None)
        if "json" in content_type.lower() or body.lstrip().startswith(("{", "[")):
            try:
                return _extract_hosts_from_json(json.loads(body), root_domain)
            except json.JSONDecodeError:
                pass
        return _candidate_hosts_from_text(body, root_domain)
    return fetch


def _dns_record_fetcher(root_domain: str, timeout: int) -> Set[str]:
    hosts: Set[str] = set()
    record_types = ["MX", "TXT", "NS", "SRV"]
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return hosts
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 5)
    names = [root_domain, f"_dmarc.{root_domain}", f"default._domainkey.{root_domain}", f"_sip._tcp.{root_domain}", f"_sip._udp.{root_domain}"]
    for name in names:
        for record_type in record_types:
            try:
                for answer in resolver.resolve(name, record_type):
                    hosts.update(_candidate_hosts_from_text(str(answer), root_domain))
            except Exception:
                continue
    return hosts


def _tls_san_fetcher(root_domain: str, timeout: int) -> Set[str]:
    hosts: Set[str] = set()
    for host in (root_domain, f"www.{root_domain}"):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=min(timeout, 8)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            for key, value in cert.get("subjectAltName", []):
                if key.lower() == "dns":
                    candidate = _normalize_host(value)
                    if candidate and _HOST_RE.match(candidate) and _is_host_within_root(candidate, root_domain):
                        hosts.add(candidate)
        except Exception:
            continue
    return hosts


def _common_web_fetcher(paths: List[str], source_url: str = "https://{domain}{path}") -> ProviderFetcher:
    def fetch(root_domain: str, timeout: int) -> Set[str]:
        hosts: Set[str] = set()
        for path in paths:
            try:
                _, body = _fetch_passive_url(source_url.format(domain=root_domain, path=path), min(timeout, 8))
                hosts.update(_candidate_hosts_from_text(body, root_domain))
            except Exception:
                continue
        return hosts
    return fetch


def _api_header(env_name: str, template: str = "{key}") -> Callable[[], Dict[str, str]]:
    return lambda: {"API-Key": template.format(key=os.getenv(env_name, ""))}


def _bearer_header(env_name: str) -> Callable[[], Dict[str, str]]:
    return lambda: {"Authorization": f"Bearer {os.getenv(env_name, '')}"}


def _public_provider(name: str, category: str, fetcher: ProviderFetcher) -> EnumerationProvider:
    # Public unauthenticated sources routinely rate-limit, retire endpoints, or
    # reject automated requests. Treat those outages as a coverage reduction, not
    # as a scan error, so the UI never reports a successful enumeration as broken.
    return EnumerationProvider(name, category, fetcher, report_errors=False)


def _all_enumeration_providers() -> List[EnumerationProvider]:
    providers = [
        # Use maintained public CT search APIs only. Several historical entries
        # (Google/Facebook CT search and log-operator names backed by crt.sh) are
        # no longer public query APIs or were duplicate aliases that produced
        # noisy 400/404 errors in the UI without adding unique coverage.
        _public_provider("crt.sh", "Certificate Transparency", _json_or_text_url_fetcher("https://crt.sh/?q=%25.{domain}&output=json")),
        _public_provider("Cert Spotter", "Certificate Transparency", _json_or_text_url_fetcher("https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names")),
        _public_provider("HackerTarget", "Passive DNS", _json_or_text_url_fetcher("https://api.hackertarget.com/hostsearch/?q={domain}")),
        _public_provider("RapidDNS", "Passive DNS", _json_or_text_url_fetcher("https://rapiddns.io/subdomain/{domain}?full=1")),
        _public_provider("AlienVault OTX", "Threat Intelligence", _json_or_text_url_fetcher("https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")),
        _public_provider("urlscan.io", "Threat Intelligence", _json_or_text_url_fetcher("https://urlscan.io/api/v1/search/?q=domain:{domain}")),
        _public_provider("Wayback Machine", "Web Archives", _json_or_text_url_fetcher("https://web.archive.org/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey")),
        _public_provider("Common Crawl", "Web Archives", _json_or_text_url_fetcher("https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{domain}/*&output=json")),
        EnumerationProvider("DNS Enumeration", "DNS Enumeration", _dns_record_fetcher),
        EnumerationProvider("Robots & Sitemap Enumeration", "Robots & Sitemap Enumeration", _common_web_fetcher(["/robots.txt", "/sitemap.xml", "/sitemap_index.xml"])),
        EnumerationProvider("HTML Enumeration", "HTML Enumeration", _common_web_fetcher(["/", "/index.html"])),
        EnumerationProvider("JavaScript Enumeration", "JavaScript Enumeration", _common_web_fetcher(["/", "/app.js", "/main.js"])),
        EnumerationProvider("Certificate Collection", "Certificate Collection", _tls_san_fetcher),
    ]
    api_providers = [
        ("SecurityTrails", "Passive DNS", "https://api.securitytrails.com/v1/domain/{domain}/subdomains", "SECURITYTRAILS_API_KEY", _api_header("SECURITYTRAILS_API_KEY")),
        ("DNSDB (Farsight)", "Passive DNS", "https://api.dnsdb.info/lookup/rrset/name/*.{domain}/ANY", "DNSDB_API_KEY", _api_header("DNSDB_API_KEY", "Bearer {key}")),
        ("RiskIQ PassiveTotal", "Passive DNS", "https://api.riskiq.net/pt/v2/enrichment/subdomains?query={domain}", "PASSIVETOTAL_API_KEY", _api_header("PASSIVETOTAL_API_KEY")),
        ("WhoisXML API", "Passive DNS", "https://subdomains.whoisxmlapi.com/api/v1?domainName={domain}&apiKey=" + os.getenv("WHOISXML_API_KEY", ""), "WHOISXML_API_KEY", None),
        ("VirusTotal Domains", "Passive DNS", "https://www.virustotal.com/api/v3/domains/{domain}/subdomains", "VIRUSTOTAL_API_KEY", lambda: {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY", "")}),
        ("Shodan", "Internet-wide Search Engines", "https://api.shodan.io/dns/domain/{domain}?key=" + os.getenv("SHODAN_API_KEY", ""), "SHODAN_API_KEY", None),
        ("Censys", "Internet-wide Search Engines", "https://search.censys.io/api/v2/hosts/search?q={domain}", "CENSYS_API_KEY", _bearer_header("CENSYS_API_KEY")),
        ("FOFA", "Internet-wide Search Engines", "https://fofa.info/api/v1/search/all?key=" + os.getenv("FOFA_API_KEY", "") + "&qbase64={domain}", "FOFA_API_KEY", None),
        ("ZoomEye", "Internet-wide Search Engines", "https://api.zoomeye.org/host/search?query={domain}", "ZOOMEYE_API_KEY", _api_header("ZOOMEYE_API_KEY")),
        ("GitHub code search", "Git Repository Enumeration", "https://api.github.com/search/code?q={domain}", "GITHUB_TOKEN", _bearer_header("GITHUB_TOKEN")),
    ]
    for name, category, url, env, headers in api_providers:
        providers.append(EnumerationProvider(name, category, _json_or_text_url_fetcher(url, headers), env))
    # Optional providers whose API endpoints, credentials, or commercial plans vary.
    # Set the corresponding *_URL template (containing {domain}) to enable them;
    # otherwise they are reported as skipped without affecting the scan.
    configurable = {
        "DNSlytics": ("Passive DNS", "DNSLYTICS_URL"), "ViewDNS": ("Passive DNS", "VIEWDNS_URL"), "IBM X-Force Exchange": ("Passive DNS", "XFORCE_URL"), "CIRCL Passive DNS": ("Passive DNS", "CIRCL_PDNS_URL"), "OpenINTEL": ("Passive DNS", "OPENINTEL_URL"),
        "Hunter How": ("Internet-wide Search Engines", "HUNTERHOW_URL"), "CriminalIP": ("Internet-wide Search Engines", "CRIMINALIP_URL"), "Netlas": ("Internet-wide Search Engines", "NETLAS_URL"), "BinaryEdge": ("Internet-wide Search Engines", "BINARYEDGE_URL"), "LeakIX": ("Internet-wide Search Engines", "LEAKIX_URL"), "ONYPHE": ("Internet-wide Search Engines", "ONYPHE_URL"),
        "Pulsedive": ("Threat Intelligence", "PULSEDIVE_URL"), "GreyNoise": ("Threat Intelligence", "GREYNOISE_URL"), "Arquivo.pt": ("Web Archives", "ARQUIVO_URL"), "Archive.today": ("Web Archives", "ARCHIVE_TODAY_URL"),
        "Google Search": ("Search Engine Enumeration", "GOOGLE_SEARCH_URL"), "Bing": ("Search Engine Enumeration", "BING_SEARCH_URL"), "Brave Search": ("Search Engine Enumeration", "BRAVE_SEARCH_URL"), "DuckDuckGo": ("Search Engine Enumeration", "DUCKDUCKGO_URL"), "Yahoo": ("Search Engine Enumeration", "YAHOO_URL"), "Yandex": ("Search Engine Enumeration", "YANDEX_URL"),
        "GitLab": ("Git Repository Enumeration", "GITLAB_SEARCH_URL"), "Bitbucket": ("Git Repository Enumeration", "BITBUCKET_SEARCH_URL"), "Sourcegraph": ("Git Repository Enumeration", "SOURCEGRAPH_URL"), "Codeberg": ("Git Repository Enumeration", "CODEBERG_URL"),
        "AWS CloudFront": ("Cloud Service Discovery", "CLOUD_DISCOVERY_URL"), "AWS API Gateway": ("Cloud Service Discovery", "CLOUD_DISCOVERY_URL"), "Azure App Service": ("Cloud Service Discovery", "CLOUD_DISCOVERY_URL"), "Azure Front Door": ("Cloud Service Discovery", "CLOUD_DISCOVERY_URL"), "Google Cloud Run": ("Cloud Service Discovery", "CLOUD_DISCOVERY_URL"), "Firebase Hosting": ("Cloud Service Discovery", "CLOUD_DISCOVERY_URL"),
    }
    for name, (category, env) in configurable.items():
        url_template = os.getenv(env, "https://disabled.invalid/?q={domain}")
        providers.append(EnumerationProvider(name, category, _json_or_text_url_fetcher(url_template), env))
    return providers


def _merge_source_hosts(found_by_source: Dict[str, List[str]]) -> Dict[str, List[str]]:
    host_sources: Dict[str, List[str]] = {}
    for source, hosts in found_by_source.items():
        for host in hosts:
            host_sources.setdefault(host, []).append(source)
    return {host: sorted(set(sources)) for host, sources in sorted(host_sources.items())}

def _passive_source_urls(root_domain: str) -> Dict[str, str]:
    # Kept for compatibility with older tests and raw command summaries.
    return {provider.name: "provider://" + provider.name for provider in _all_enumeration_providers() if provider.enabled()}

def enumerate_passive_subdomains(root_domain: str, timeout: int = PASSIVE_SOURCE_TIMEOUT) -> Dict[str, object]:
    """Run passive/active modular providers concurrently and aggregate results.

    Every provider is isolated: API-key providers are skipped when their key is
    missing, failures are recorded per source, and all hostnames are normalized
    before source tagging and deduplication.
    """
    found_by_source: Dict[str, List[str]] = {}
    errors: Dict[str, str] = {}
    skipped: List[str] = []
    providers = _all_enumeration_providers()

    def run_provider(provider: EnumerationProvider) -> Tuple[str, Set[str], Optional[str], bool]:
        if not provider.enabled():
            return provider.name, set(), None, True
        try:
            normalized_hosts = {
                host
                for raw_host in provider.run(root_domain, timeout)
                for host in [_normalize_host(raw_host)]
                if host and _HOST_RE.match(host) and _is_host_within_root(host, root_domain)
            }
            return provider.name, normalized_hosts, None, False
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, socket.timeout, OSError, ValueError) as exc:
            return provider.name, set(), str(exc)[:500], False
        except Exception as exc:
            log.debug("Subdomain provider %s failed for %s", provider.name, root_domain, exc_info=True)
            return provider.name, set(), str(exc)[:500], False

    workers = max(1, min(MAX_ENUM_PROVIDER_WORKERS, len(providers)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run_provider, provider): provider for provider in providers}
        for future in as_completed(futures):
            source, hosts, error, was_skipped = future.result()
            if was_skipped:
                skipped.append(source)
                continue
            found_by_source[source] = sorted(hosts)
            if error and futures[future].report_errors:
                errors[source] = error

    host_sources = _merge_source_hosts(found_by_source)
    all_hosts = sorted(host_sources)
    return {
        "root_domain": root_domain,
        "found": all_hosts,
        "sources": found_by_source,
        "host_sources": host_sources,
        "errors": errors,
        "skipped": sorted(skipped),
    }

def _active_subfinder_project_count() -> int:
    with _sf_lock:
        return sum(1 for state in _sf_state.values() if state.get("status") in ACTIVE_SUBFINDER_STATUSES)



def _resolve_subfinder_bin() -> Optional[str]:
    path = shutil.which("subfinder")
    if path:
        return path
    fallback = "/usr/local/bin/subfinder"
    return fallback if Path(fallback).exists() else None


def subfinder_available() -> bool:
    return bool(_resolve_subfinder_bin())


def _subfinder_supports_all_flag(subfinder_bin: str) -> bool:
    """
    Detect whether the installed subfinder binary supports '-all'.
    Some environments ship older builds where this flag is unavailable.
    """
    global _subfinder_all_flag_supported
    if _subfinder_all_flag_supported is not None:
        return _subfinder_all_flag_supported
    try:
        help_result = subprocess.run(
            [subfinder_bin, "-h"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        help_text = f"{help_result.stdout}\n{help_result.stderr}".lower()
        _subfinder_all_flag_supported = "-all" in help_text
    except Exception:
        # Be permissive on detection failure: prefer baseline command without -all.
        _subfinder_all_flag_supported = False
    return _subfinder_all_flag_supported


def _build_subfinder_cmd(subfinder_bin: str, root_domain: str) -> List[str]:
    cmd = [subfinder_bin, "-d", root_domain, "-silent", "-timeout", "30"]
    if _subfinder_supports_all_flag(subfinder_bin):
        cmd.append("-all")
    return cmd


def _run_subfinder_for_root(root_domain: str, timeout: int = 180) -> Dict[str, object]:
    subfinder_bin = _resolve_subfinder_bin()
    cmd = _build_subfinder_cmd(subfinder_bin, root_domain) if subfinder_bin else []
    command_str = " ".join(cmd) if cmd else "subfinder binary not found"
    subfinder_stdout = ""
    subfinder_stderr = ""
    subfinder_code = None
    subfinder_found: List[str] = []
    try:
        if subfinder_bin:
            log.info("Subfinder start (bin=%s): %s", subfinder_bin, " ".join(cmd))
            log_event("subfinder", "info", "Subfinder command started", root_domain=root_domain, command=" ".join(cmd), status="running")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            subfinder_stdout = result.stdout or ""
            subfinder_stderr = result.stderr or ""
            subfinder_code = result.returncode
            raw_lines = [ln.strip().lower() for ln in subfinder_stdout.splitlines() if ln.strip()]
            subfinder_found = sorted(
                {
                    candidate
                    for ln in raw_lines
                    for candidate in [_normalize_host(ln)]
                    if candidate
                    and _HOST_RE.match(candidate)
                    and _is_host_within_root(candidate, root_domain)
                }
            )
        else:
            subfinder_stderr = "subfinder binary not found in PATH or /usr/local/bin/subfinder"
            subfinder_code = 127

        found = sorted(subfinder_found)
        status = "done" if subfinder_code == 0 else "error"
        stdout = subfinder_stdout
        stderr = subfinder_stderr
        log.info("Subfinder enumeration finished root=%s subfinder_exit=%s discovered=%d", root_domain, subfinder_code, len(found))
        return {
            "root_domain": root_domain,
            "command": command_str,
            "status": status,
            "exit_code": subfinder_code,
            "stdout": stdout,
            "stderr": stderr,
            "found": found,
            "sources": {host: ["Subfinder"] for host in found},
        }
    except subprocess.TimeoutExpired:
        msg = f"Subfinder timed out after {timeout}s for {root_domain}"
        log.error(msg)
        return {
            "root_domain": root_domain,
            "command": command_str,
            "status": "timeout",
            "exit_code": None,
            "stdout": "",
            "stderr": msg,
            "found": [],
        }
    except Exception as e:
        log.exception("Subfinder execution error: %s", e)
        return {
            "root_domain": root_domain,
            "command": command_str,
            "status": "error",
            "exit_code": None,
            "stdout": "",
            "stderr": str(e),
            "found": [],
        }


_HOST_RE = re.compile(r"^(?:\*\.)?(?=.{1,253}$)(?!-)[a-z0-9-]+(?:\.[a-z0-9-]+)+$", re.IGNORECASE)
_COMMON_COMPOUND_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp",
    "com.br", "com.mx", "com.tr",
}


def _normalize_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""

    # Project host lists often contain full URLs copied from discovery output.
    # urlparse only treats values as URLs when a scheme is present, so also
    # support schemeless entries such as example.com/path or user@example.com:8443.
    parse_target = h if "://" in h else f"//{h}"
    try:
        parsed = urlparse(parse_target)
        if parsed.hostname:
            h = parsed.hostname
        elif "://" in h:
            h = h.split("://", 1)[1].split("/", 1)[0]
    except Exception:
        if "://" in h:
            h = h.split("://", 1)[1].split("/", 1)[0]

    h = h.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    if h.startswith("*."):
        h = h[2:]
    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]
    elif ":" in h:
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def _registrable_domain(host: str) -> Optional[str]:
    try:
        import tldextract
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass

    parts = host.split(".")
    if len(parts) < 2:
        return None
    tail2 = ".".join(parts[-2:])
    tail3 = ".".join(parts[-3:]) if len(parts) >= 3 else ""
    if tail2 in _COMMON_COMPOUND_SUFFIXES and len(parts) >= 3:
        return tail3
    return tail2


def _extract_project_root_domains(hosts: List[str]) -> List[str]:
    """Extract registrable root domains from a project host list."""
    normalized: List[str] = []
    for raw in hosts:
        raw_line = (raw or "").strip()
        if not raw_line:
            continue
        for token in re.split(r"[\s,;]+", raw_line):
            h = _normalize_host(token)
            if not h or "." not in h or not _HOST_RE.match(h):
                continue
            normalized.append(h)

    if not normalized:
        return []

    roots: Set[str] = set()
    for h in normalized:
        root = _registrable_domain(h)
        if root:
            roots.add(root)

    return sorted(roots)


def _is_host_within_root(host: str, root_domain: str) -> bool:
    if host == root_domain:
        return True
    return host.endswith(f".{root_domain}")


def enumerate_subdomains_for_domain(domain: str, timeout: int = 180) -> Dict[str, object]:
    """Enumerate subdomains for a single user-supplied domain."""
    normalized = _normalize_host(domain)
    if not normalized or not _HOST_RE.match(normalized):
        raise ValueError("valid domain is required")
    run = _run_subfinder_for_root(normalized, timeout=timeout)
    return {
        "root_domain": normalized,
        "command": run.get("command", ""),
        "status": run.get("status", "error"),
        "exit_code": run.get("exit_code"),
        "stderr": run.get("stderr", ""),
        "total_found": len(run.get("found") or []),
        "subdomains": run.get("found") or [],
        "sources": run.get("sources", {}),
    }


def run_subfinder_for_project(project_id: str, triggered_by: str = "scheduler") -> Optional[str]:
    """
    Full subfinder pipeline for a project:
      - extract root domains from project host list
      - run subfinder
      - store new hosts
      - trigger SSL scan on new hosts
    Returns job_id or None on failure.
    """
    from db.database import (
        project_get, project_hosts, subfinder_job_create, subfinder_job_finish,
        subfinder_job_error, subfinder_hosts_add_batch, subfinder_raw_result_add,
        subfinder_raw_result_finish, subfinder_new_discoveries_add_batch,
        subfinder_hosts_new_unscanned
    )

    project = project_get(project_id)
    if not project:
        with _sf_lock:
            _sf_state[project_id] = {"status": "error", "job_id": None, "new_count": 0, "phase": "Project lookup failed", "root_domains": []}
        return None

    with _sf_lock:
        queued = _sf_state.get(project_id, {})
        _sf_state[project_id] = {
            **queued,
            "status": "extracting_roots",
            "job_id": None,
            "new_count": 0,
            "root_domains": [],
            "phase": "Extracting root domains from selected project hosts",
            "progress": {"completed_roots": 0, "total_roots": 0},
        }

    hosts = project_hosts(project_id)
    if not hosts:
        log.warning("Subfinder: project '%s' has no base hosts", project["name"])
        log_event("subfinder", "error", "No base hosts found for project", project_id=project_id, status="failed")
        with _sf_lock:
            _sf_state[project_id] = {"status": "error", "job_id": None, "new_count": 0, "phase": "No base hosts found for project", "root_domains": []}
        return None

    root_domains = _extract_project_root_domains(hosts)
    if not root_domains:
        log_event("subfinder", "error", "Unable to extract root domains", project_id=project_id, status="failed")
        with _sf_lock:
            _sf_state[project_id] = {"status": "error", "job_id": None, "new_count": 0, "phase": "Unable to extract root domains", "root_domains": []}
        return None

    with _sf_lock:
        _sf_state[project_id].update({
            "status": "running",
            "root_domains": root_domains,
            "phase": f"Starting subdomain enumeration for {len(root_domains)} extracted root domain(s)",
            "progress": {"completed_roots": 0, "total_roots": len(root_domains)},
            "current_root": None,
        })

    if not subfinder_available():
        log.warning("Subfinder binary not found. Checked PATH and /usr/local/bin/subfinder")
        log_event("subfinder", "error", "Subfinder binary not found", project_id=project_id, status="failed")

    log.info("Subfinder starting for '%s' — root domains: %s", project["name"], ", ".join(root_domains))
    log_event(
        "subfinder",
        "info",
        "Subfinder started",
        project_id=project_id,
        root_domains=root_domains,
        status="running",
    )

    job_id = subfinder_job_create(project_id, ",".join(root_domains), triggered_by)

    with _sf_lock:
        _sf_state[project_id].update({"status": "running", "job_id": job_id, "new_count": 0})

    try:
        raw_records = []
        discovered_all: List[str] = []
        raw_ids = {
            root_domain: subfinder_raw_result_add(
                job_id=job_id,
                project_id=project_id,
                root_domain=root_domain,
                command=" ".join(_build_subfinder_cmd("subfinder", root_domain)),
            )
            for root_domain in root_domains
        }
        workers = max(1, min(8, len(root_domains)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_run_subfinder_for_root, root_domain): root_domain for root_domain in root_domains}
            for future in as_completed(futures):
                root_domain = futures[future]
                with _sf_lock:
                    _sf_state[project_id].update({
                        "current_root": root_domain,
                        "phase": f"Enumerating subdomains for {root_domain}",
                    })
                run = future.result()
                raw_records.append(
                    {
                        "root_domain": run["root_domain"],
                        "command": run["command"],
                        "status": run["status"],
                        "exit_code": run["exit_code"],
                        "found_count": len(run["found"]),
                    }
                )
                discovered_all.extend(run["found"])
                subfinder_raw_result_finish(
                    raw_ids[root_domain],
                    run["status"],
                    run["exit_code"],
                    len(run["found"]),
                    run["stdout"],
                    run["stderr"],
                )
                with _sf_lock:
                    progress = dict(_sf_state[project_id].get("progress") or {})
                    progress["completed_roots"] = int(progress.get("completed_roots", 0)) + 1
                    progress["total_roots"] = len(root_domains)
                    _sf_state[project_id].update({
                        "progress": progress,
                        "phase": f"Completed {progress['completed_roots']} of {progress['total_roots']} root domains",
                    })
                if run["status"] != "done":
                    log.warning(
                        "Subfinder run for root=%s finished with status=%s stderr=%s",
                        root_domain,
                        run["status"],
                        (run["stderr"] or "").strip()[:500],
                    )
                elif len(run["found"]) == 0:
                    log.warning("Subfinder returned 0 results — check sources/config (root=%s)", root_domain)

        discovered = sorted(set(discovered_all))
        new_count, new_hosts = subfinder_hosts_add_batch(project_id, discovered)
        subfinder_new_discoveries_add_batch(job_id, project_id, new_hosts)
        # A previous project subdomain run may have discovered hosts but failed
        # during the SSL phase.  Scan both this run's new hosts and any older
        # unscanned subfinder hosts so rerunning the project integration can
        # complete and produce certificate results instead of reporting no work.
        scan_hosts = sorted(set(new_hosts) | set(subfinder_hosts_new_unscanned(project_id)))

        raw_dir = Path("data/subfinder_raw")
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_output_path = raw_dir / f"{job_id}.json.gz"
        with gzip.open(raw_output_path, "wt", encoding="utf-8") as fp:
            json.dump(raw_records, fp, separators=(",", ":"))
        subfinder_job_finish(job_id, new_count, len(discovered), str(raw_output_path))

        if not discovered:
            log.warning("Subfinder returned 0 results — check sources/config")
            log_event("subfinder", "warning", "Subfinder returned 0 results — check sources/config", project_id=project_id, job_id=job_id, status="idle")
            with _sf_lock:
                _sf_state[project_id].update({"status": "done", "job_id": job_id, "new_count": 0, "phase": "Enumeration completed with 0 results", "current_root": None})
            return job_id

        with _sf_lock:
            _sf_state[project_id]["new_count"] = new_count
            _sf_state[project_id]["status"] = "ssl_scanning" if scan_hosts else "done"
            _sf_state[project_id]["phase"] = f"Discovered {new_count} new hosts; {len(scan_hosts)} pending SSL scans"
            _sf_state[project_id]["current_root"] = None

        log.info(
            "Subfinder: %d new hosts (%d pending SSL scans) for '%s'",
            new_count,
            len(scan_hosts),
            project["name"],
        )
        log_event(
            "subfinder",
            "info",
            f"Discovered {new_count} new hosts; {len(scan_hosts)} pending SSL scans",
            project_id=project_id,
            job_id=job_id,
            status="running" if scan_hosts else "idle",
        )

        if scan_hosts:
            _ssl_scan_subfinder_hosts(project_id, scan_hosts, job_id)

        with _sf_lock:
            _sf_state[project_id]["status"] = "done"
            _sf_state[project_id]["phase"] = "Subfinder workflow completed"
        log_event("subfinder", "info", "Subfinder workflow completed", project_id=project_id, job_id=job_id, status="idle")

        return job_id

    except Exception as e:
        log.exception("Subfinder pipeline error for '%s': %s", project["name"], e)
        subfinder_job_error(job_id, str(e))
        log_event("subfinder", "error", f"Subfinder pipeline failed: {e}", project_id=project_id, job_id=job_id, status="failed")
        with _sf_lock:
            if project_id in _sf_state:
                _sf_state[project_id]["status"] = "error"
                _sf_state[project_id]["phase"] = str(e)
        return None


def _ssl_scan_subfinder_hosts(project_id: str, hostnames: List[str], job_id: str):
    """Run SSL checks on newly discovered subfinder hosts and save results."""
    from db.database import (
        scan_create, scan_finish, results_batch_save,
        subfinder_hosts_mark_scanned, alert_add, scan_progress
    )
    from core.ssl_checker import run_checker
    from scheduler.runner import BATCH_SIZE, PROGRESS_UPDATE_EVERY, MAX_WORKERS, _scan_lock, _scan_state

    if not hostnames:
        return

    total = len(hostnames)
    scan = scan_create(project_id, total, by=f"subfinder:{job_id}")
    scan_id = scan["id"]

    with _scan_lock:
        _scan_state[scan_id] = {
            "status": "running", "progress": 0, "total": total,
            "project_id": project_id, "project_name": f"subfinder-{project_id[:8]}",
            "started_at": datetime.now(timezone.utc).isoformat()
        }

    result_batch = []
    done_count = [0]
    lock = threading.Lock()
    scanned_hosts = []

    def on_result(done, total_inner, r):
        hostname = r.get("hostname", "")
        scanned_hosts.append(hostname)

        if r.get("is_mismatch") and not r.get("error"):
            mismatch_scope = "same_domain" if r.get("same_base") else "different_domain"
            alert_add(project_id, hostname, "SSL Mismatch",
                      f"[Subfinder] CN '{r.get('cn','?')}' ≠ hostname", scan_id, mismatch_scope=mismatch_scope)
        elif r.get("is_expired") and not r.get("error"):
            alert_add(project_id, hostname, "Expired",
                      f"[Subfinder] Expired {r.get('expiry','?')}", scan_id)
        elif r.get("is_expiring_soon") and not r.get("error"):
            alert_add(project_id, hostname, "Expiring Soon",
                      f"[Subfinder] Expires {r.get('expiry','?')} ({r.get('days_left')}d)", scan_id)

        with lock:
            result_batch.append(r)
            done_count[0] += 1
            if len(result_batch) >= BATCH_SIZE:
                batch = result_batch[:]
                result_batch.clear()
                results_batch_save(scan_id, project_id, batch)
            if done_count[0] % PROGRESS_UPDATE_EVERY == 0:
                scan_progress(scan_id, done_count[0])
                with _scan_lock:
                    if scan_id in _scan_state:
                        _scan_state[scan_id]["progress"] = done_count[0]

    try:
        # Reuse the scheduler-wide SSL worker cap instead of spawning a hard-coded
        # 200-thread pool for every subfinder project.  Auto subfinder can run for
        # multiple enabled projects from the background scheduler; keeping this
        # bounded prevents thread exhaustion from taking down the web worker.
        run_checker(
            hostnames,
            max_workers=MAX_WORKERS,
            progress_callback=on_result,
            collect_results=False,
        )

        with lock:
            if result_batch:
                results_batch_save(scan_id, project_id, result_batch)

        scan_finish(scan_id)
        subfinder_hosts_mark_scanned(project_id, scanned_hosts)

        with _scan_lock:
            if scan_id in _scan_state:
                _scan_state[scan_id]["status"] = "done"
                _scan_state[scan_id]["progress"] = total
    except Exception as e:
        log.exception("Subfinder SSL scan failed for project=%s job=%s: %s", project_id, job_id, e)
        from db.database import scan_update
        scan_update(scan_id, status="error", finished_at=datetime.now(timezone.utc).isoformat())
        with _scan_lock:
            if scan_id in _scan_state:
                _scan_state[scan_id]["status"] = "error"
        raise



def projects_with_root_domains() -> List[Dict[str, object]]:
    """Return projects that have host-list entries which resolve to root domains."""
    from db.database import project_hosts, project_list

    projects: List[Dict[str, object]] = []
    for project in project_list():
        roots = _extract_project_root_domains(project_hosts(project["id"]))
        if roots:
            item = dict(project)
            item["root_domains"] = roots
            projects.append(item)
    return projects


def run_subfinder_for_all_projects_async(triggered_by: str = "manual") -> int:
    """Run project subfinder integrations for every project with root domains."""
    candidates = projects_with_root_domains()
    if not candidates:
        return 0
    with _sf_lock:
        active_count = sum(
            1 for state in _sf_state.values()
            if state.get("status") in ACTIVE_SUBFINDER_STATUSES
        )
        if active_count >= MAX_CONCURRENT_SUBFINDER_PROJECTS:
            return 0
        for project in candidates:
            _sf_state[project["id"]] = {
                "status": "queued",
                "job_id": None,
                "new_count": 0,
                "phase": "Queued for root-domain extraction",
                "root_domains": [],
                "progress": {"completed_roots": 0, "total_roots": 0},
            }

    def worker():
        for project in candidates:
            pid = project["id"]
            try:
                run_subfinder_for_project(pid, triggered_by=triggered_by)
            except Exception:
                log.exception("Subfinder all-project run failed for project=%s", pid)
                with _sf_lock:
                    _sf_state[pid] = {"status": "error", "job_id": None, "new_count": 0, "phase": "Subfinder all-project run failed", "root_domains": []}

    t = threading.Thread(target=worker, daemon=True, name="sf-all-projects")
    t.start()
    return len(candidates)

def run_subfinder_async(project_id: str, triggered_by: str = "manual") -> bool:
    """Start subfinder pipeline in background thread. Returns False if at capacity."""
    with _sf_lock:
        if _sf_state.get(project_id, {}).get("status") in ACTIVE_SUBFINDER_STATUSES:
            return False
        active_count = sum(
            1 for state in _sf_state.values()
            if state.get("status") in ACTIVE_SUBFINDER_STATUSES
        )
        if active_count >= MAX_CONCURRENT_SUBFINDER_PROJECTS:
            return False
        # Reserve the slot before starting the thread. Without this, the
        # scheduler can launch many project threads in one tick before each
        # worker has time to mark itself running, exhausting process threads
        # once their SSL scans begin.
        _sf_state[project_id] = {"status": "queued", "job_id": None, "new_count": 0, "phase": "Queued for root-domain extraction", "root_domains": [], "progress": {"completed_roots": 0, "total_roots": 0}}

    t = threading.Thread(
        target=run_subfinder_for_project,
        args=(project_id, triggered_by),
        daemon=True,
        name=f"sf-{project_id[:8]}"
    )
    t.start()
    return True


def get_sf_state(project_id: str) -> dict:
    with _sf_lock:
        return _sf_state.get(project_id, {}).copy()


# ── Subfinder Scheduler ───────────────────────────────────────────────────────

class SubfinderScheduler:
    def __init__(self):
        self._thread = None
        self._stop = threading.Event()
        self._last_run = {}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="sf-scheduler")
        self._thread.start()
        log.info("Subfinder scheduler started (binary %s)",
                 "found" if subfinder_available() else "NOT FOUND — install subfinder")

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as e:
                log.exception("Subfinder scheduler error: %s", e)
            self._stop.wait(60)

    def _tick(self):
        from db.database import project_list
        now_ts = time.time()
        for p in project_list():
            if not p.get("enabled") or not p.get("subfinder_enabled"):
                continue
            pid = p["id"]
            interval_min = max(10, min(30, int(p.get("subfinder_interval_minutes", 30) or 30)))
            interval_s = interval_min * 60
            if now_ts - self._last_run.get(pid, 0) >= interval_s:
                if _active_subfinder_project_count() >= MAX_CONCURRENT_SUBFINDER_PROJECTS:
                    # Keep scheduled auto-enumeration serialized by default so
                    # multiple enabled projects cannot create overlapping
                    # subfinder subprocess pools plus SSL thread pools.
                    continue
                if run_subfinder_async(pid, triggered_by="scheduler"):
                    self._last_run[pid] = now_ts


_sf_scheduler = SubfinderScheduler()


def start_subfinder_scheduler():
    _sf_scheduler.start()

def stop_subfinder_scheduler():
    _sf_scheduler.stop()
