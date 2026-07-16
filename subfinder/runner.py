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
import select
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import threading
import time
import queue
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from core.observability import log_event, publish

log = logging.getLogger(__name__)

SUBFINDER_BIN = shutil.which("subfinder") or "/usr/local/bin/subfinder"
_sf_lock = threading.Lock()
_sf_state = {}  # project_id -> {status, job_id, new_count}
_subfinder_all_flag_supported: Optional[bool] = None
MAX_CONCURRENT_SUBFINDER_PROJECTS = max(1, int(os.getenv("SUBFINDER_MAX_CONCURRENT_PROJECTS", "1")))
ACTIVE_SUBFINDER_STATUSES = {"queued", "running", "ssl_scanning"}

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


def _run_subfinder_for_root(root_domain: str, timeout: int = 180, live_result_id: Optional[str] = None, live_project_id: Optional[str] = None, live_job_id: Optional[str] = None, live_ssl_scanner: Optional[Any] = None) -> Dict[str, object]:
    subfinder_bin = _resolve_subfinder_bin()
    cmd = _build_subfinder_cmd(subfinder_bin, root_domain) if subfinder_bin else []
    subfinder_command = " ".join(cmd) if cmd else "subfinder binary not found"
    command_str = subfinder_command

    def run_subfinder() -> Tuple[List[str], str, str, Optional[int], str]:
        if not subfinder_bin:
            return [], "", "subfinder binary not found in PATH or /usr/local/bin/subfinder", 127, "error"
        log.info("Subfinder start (bin=%s): %s", subfinder_bin, " ".join(cmd))
        log_event("subfinder", "info", "Subfinder command started", root_domain=root_domain, command=" ".join(cmd), status="running")
        if not live_result_id:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            stdout = result.stdout or ""
            raw_lines = [ln.strip().lower() for ln in stdout.splitlines() if ln.strip()]
            found = sorted(
                {
                    candidate
                    for ln in raw_lines
                    for candidate in [_normalize_host(ln)]
                    if candidate
                    and _HOST_RE.match(candidate)
                    and _is_host_within_root(candidate, root_domain)
                }
            )
            return found, stdout, result.stderr or "", result.returncode, "done" if result.returncode == 0 else "error"

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        found_set: Set[str] = set()
        stdout_lines: List[str] = []
        last_live_update = 0.0

        live_new_seen: Set[str] = set()

        def flush_live(force: bool = False):
            nonlocal last_live_update
            if not live_result_id:
                return
            current = time.monotonic()
            if not force and current - last_live_update < 0.75:
                return
            from db import database as db
            current_found = sorted(found_set)
            db.subfinder_raw_result_update_live(live_result_id, "\n".join(current_found), status="running")
            if live_project_id and live_job_id and current_found:
                _, new_hosts = db.subfinder_hosts_add_batch(live_project_id, current_found)
                fresh_hosts = [h for h in new_hosts if h not in live_new_seen]
                if fresh_hosts:
                    live_new_seen.update(fresh_hosts)
                    db.subfinder_new_discoveries_add_batch(live_job_id, live_project_id, fresh_hosts)
                    if live_ssl_scanner:
                        live_ssl_scanner.submit(fresh_hosts)
                    with _sf_lock:
                        state = _sf_state.get(live_project_id)
                        if state:
                            state["new_count"] = int(state.get("new_count") or 0) + len(fresh_hosts)
                            state["total_found"] = len(set(state.get("live_found", [])) | set(current_found))
                            state["live_found"] = sorted(set(state.get("live_found", [])) | set(current_found))
            last_live_update = current

        try:
            assert proc.stdout is not None
            deadline = time.monotonic() + timeout
            stdout_fd = proc.stdout.fileno()
            while True:
                if time.monotonic() > deadline:
                    proc.kill()
                    raise subprocess.TimeoutExpired(cmd, timeout)
                ready, _, _ = select.select([stdout_fd], [], [], 0.25)
                if ready:
                    line = proc.stdout.readline()
                    if line:
                        stdout_lines.append(line)
                        candidate = _normalize_host(line.strip().lower())
                        if candidate and _HOST_RE.match(candidate) and _is_host_within_root(candidate, root_domain):
                            before = len(found_set)
                            found_set.add(candidate)
                            if len(found_set) != before:
                                flush_live()
                    elif proc.poll() is not None:
                        break
                elif proc.poll() is not None:
                    for line in proc.stdout.readlines():
                        stdout_lines.append(line)
                        candidate = _normalize_host(line.strip().lower())
                        if candidate and _HOST_RE.match(candidate) and _is_host_within_root(candidate, root_domain):
                            found_set.add(candidate)
                    break
            proc.wait(timeout=1)
        finally:
            flush_live(force=True)

        stderr = proc.stderr.read() if proc.stderr else ""
        found = sorted(found_set)
        stdout = "".join(stdout_lines)
        return found, stdout, stderr or "", proc.returncode, "done" if proc.returncode == 0 else "error"

    try:
        subfinder_found, _subfinder_stdout, subfinder_stderr, subfinder_code, subfinder_status = run_subfinder()
        found = sorted(set(subfinder_found))
        host_sources: Dict[str, List[str]] = {host: ["Subfinder"] for host in found}
        status = subfinder_status
        stdout = "\n".join(found)
        stderr = subfinder_stderr.strip()
        log.info("Subfinder enumeration finished root=%s subfinder_exit=%s discovered=%d", root_domain, subfinder_code, len(found))
        return {
            "root_domain": root_domain,
            "command": command_str,
            "status": status,
            "exit_code": subfinder_code,
            "stdout": stdout,
            "stderr": stderr,
            "found": found,
            "sources": host_sources,
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
            "sources": {},
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
            "sources": {},
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

    # Project host lists may contain full URLs as well as bare hostnames.
    # urlparse only exposes hostname for scheme/netloc URLs, so prefix bare
    # URL-shaped values (example.com/path, //example.com/path) before parsing.
    parse_target = h
    if (
        "://" not in parse_target
        and not parse_target.startswith("//")
        and any(sep in parse_target for sep in ("/", "?", "#"))
    ):
        parse_target = f"//{parse_target}"
    if "://" in parse_target or parse_target.startswith("//"):
        try:
            parsed = urlparse(parse_target)
            if parsed.hostname:
                h = parsed.hostname
            elif "://" in h:
                h = h.split("://", 1)[1].split("/", 1)[0]
            else:
                h = h.lstrip("/").split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        except Exception:
            if "://" in h:
                h = h.split("://", 1)[1].split("/", 1)[0]
            else:
                h = h.lstrip("/").split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
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
            _sf_state[project_id] = {"status": "error", "job_id": None, "new_count": 0}
        return None

    hosts = project_hosts(project_id)
    if not hosts:
        log.warning("Subfinder: project '%s' has no base hosts", project["name"])
        log_event("subfinder", "error", "No base hosts found for project", project_id=project_id, status="failed")
        with _sf_lock:
            _sf_state[project_id] = {"status": "error", "job_id": None, "new_count": 0}
        return None

    root_domains = _extract_project_root_domains(hosts)
    if not root_domains:
        log_event("subfinder", "error", "Unable to extract root domains", project_id=project_id, status="failed")
        with _sf_lock:
            _sf_state[project_id] = {"status": "error", "job_id": None, "new_count": 0}
        return None

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
        _sf_state[project_id] = {"status": "running", "job_id": job_id, "new_count": 0}

    try:
        raw_records = []
        discovered_all: List[str] = []
        live_ssl_scanner = _LiveSubfinderSSLScanner(project_id, job_id)
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
            futures = {pool.submit(_run_subfinder_for_root, root_domain, 180, raw_ids[root_domain], project_id, job_id, live_ssl_scanner): root_domain for root_domain in root_domains}
            for future in as_completed(futures):
                root_domain = futures[future]
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
        with _sf_lock:
            live_new_count = int((_sf_state.get(project_id) or {}).get("new_count") or 0)
        new_count += live_new_count
        subfinder_new_discoveries_add_batch(job_id, project_id, new_hosts)
        # A previous project subdomain run may have discovered hosts but failed
        # during the SSL phase.  Scan both this run's new hosts and any older
        # unscanned subfinder hosts so rerunning the project integration can
        # complete and produce certificate results instead of reporting no work.
        scan_hosts = sorted(set(subfinder_hosts_new_unscanned(project_id)))
        live_ssl_scanner.submit(scan_hosts)

        raw_dir = Path("data/subfinder_raw")
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_output_path = raw_dir / f"{job_id}.json.gz"
        with gzip.open(raw_output_path, "wt", encoding="utf-8") as fp:
            json.dump(raw_records, fp, separators=(",", ":"))
        subfinder_job_finish(job_id, new_count, len(discovered), str(raw_output_path))

        if not discovered:
            live_ssl_scanner.finish()
            log.warning("Subfinder returned 0 results — check sources/config")
            log_event("subfinder", "warning", "Subfinder returned 0 results — check sources/config", project_id=project_id, job_id=job_id, status="idle")
            with _sf_lock:
                _sf_state[project_id] = {"status": "done", "job_id": job_id, "new_count": 0}
            return job_id

        with _sf_lock:
            _sf_state[project_id]["new_count"] = new_count
            _sf_state[project_id]["status"] = "done"
            _sf_state[project_id]["ssl_pending"] = len(scan_hosts)

        log.info(
            "Subfinder: %d new hosts (%d queued for SSL scans) for '%s'",
            new_count,
            len(scan_hosts),
            project["name"],
        )
        log_event(
            "subfinder",
            "info",
            f"Discovered {new_count} new hosts; {len(scan_hosts)} queued for SSL scans",
            project_id=project_id,
            job_id=job_id,
            status="idle",
        )

        live_ssl_scanner.finish()

        log_event("subfinder", "info", "Subfinder workflow completed", project_id=project_id, job_id=job_id, status="idle")

        return job_id

    except Exception as e:
        log.exception("Subfinder pipeline error for '%s': %s", project["name"], e)
        subfinder_job_error(job_id, str(e))
        log_event("subfinder", "error", f"Subfinder pipeline failed: {e}", project_id=project_id, job_id=job_id, status="failed")
        with _sf_lock:
            if project_id in _sf_state:
                _sf_state[project_id]["status"] = "error"
        return None



class _LiveSubfinderSSLScanner:
    """Continuously scans newly discovered Subfinder hosts as enumeration streams in."""

    def __init__(self, project_id: str, job_id: str):
        from db.database import scan_create, project_get
        from scheduler.runner import MAX_WORKERS, _scan_lock, _scan_state

        self.project_id = project_id
        self.job_id = job_id
        self.project = project_get(project_id) or {"name": f"project-{project_id[:8]}"}
        self.scan = scan_create(project_id, 0, by=f"subfinder:{job_id}")
        self.scan_id = self.scan["id"]
        self.queue: "queue.Queue[Optional[str]]" = queue.Queue()
        self.seen: Set[str] = set()
        self.scanned_hosts: List[str] = []
        self.result_batch: List[Dict] = []
        self.done = 0
        self.total = 0
        self.lock = threading.Lock()
        workers = max(1, min(MAX_WORKERS, int(os.getenv("SUBFINDER_SSL_LIVE_WORKERS", "32"))))
        self.workers = workers
        self.threads = [threading.Thread(target=self._worker, daemon=True, name=f"sf-live-ssl-{job_id[:8]}-{i}") for i in range(workers)]
        with _scan_lock:
            _scan_state[self.scan_id] = {
                "id": self.scan_id, "status": "running", "progress": 0, "done": 0, "total": 0,
                "project_id": project_id, "project_name": self.project.get("name") or f"project-{project_id[:8]}",
                "source": "subfinder", "subfinder_job_id": job_id,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
        publish("scan_update", {"id": self.scan_id, "status": "running", "progress": 0, "done": 0, "total": 0, "project_id": project_id, "source": "subfinder", "subfinder_job_id": job_id})
        for thread in self.threads:
            thread.start()

    def submit(self, hostnames: List[str]) -> None:
        from db.database import scan_update
        new_hosts = []
        with self.lock:
            for host in hostnames:
                if host and host not in self.seen:
                    self.seen.add(host)
                    new_hosts.append(host)
            if not new_hosts:
                return
            self.total += len(new_hosts)
            total = self.total
        scan_update(self.scan_id, total=total)
        from scheduler.runner import _scan_lock, _scan_state
        with _scan_lock:
            if self.scan_id in _scan_state:
                _scan_state[self.scan_id]["total"] = total
        publish("scan_update", {"id": self.scan_id, "status": "running", "progress": self.done, "done": self.done, "total": total, "project_id": self.project_id, "source": "subfinder", "subfinder_job_id": self.job_id})
        for host in new_hosts:
            self.queue.put(host)

    def _worker(self) -> None:
        from core.ssl_checker import get_cert_info
        while True:
            host = self.queue.get()
            try:
                if host is None:
                    return
                self._record_result(get_cert_info(host))
            finally:
                self.queue.task_done()

    def _record_result(self, r: Dict) -> None:
        from db.database import results_batch_save, alert_add, scan_progress, alerts_unseen_count, alert_settings_get
        from scheduler.runner import BATCH_SIZE, _scan_lock, _scan_state, _build_alert_from_result
        alert_settings = alert_settings_get()
        expiring_threshold = max(1, min(365, int(alert_settings.get("minimum_days_left") or 30)))
        hostname = r.get("hostname", "")
        alert = _build_alert_from_result(r, expiring_threshold)
        with self.lock:
            self.scanned_hosts.append(hostname)
            self.result_batch.append(r)
            self.done += 1
            done, total = self.done, self.total
            batch = []
            if len(self.result_batch) >= BATCH_SIZE:
                batch = self.result_batch[:]
                self.result_batch.clear()
        if batch:
            results_batch_save(self.scan_id, self.project_id, batch)
        if alert:
            h, issue, detail, scope = alert
            alert_add(self.project_id, h, issue, f"[Subfinder] {detail}", self.scan_id, mismatch_scope=scope)
            publish("alert_update", {"unseen_count": alerts_unseen_count()})
        scan_progress(self.scan_id, done)
        with _scan_lock:
            if self.scan_id in _scan_state:
                _scan_state[self.scan_id].update({"progress": done, "done": done, "total": total})
        publish("scan_result", {"scan_id": self.scan_id, "project_id": self.project_id, "source": "subfinder", "row": r})
        publish("scan_update", {"id": self.scan_id, "status": "running", "progress": done, "done": done, "total": total, "project_id": self.project_id, "source": "subfinder", "subfinder_job_id": self.job_id})

    def finish(self) -> None:
        from db.database import results_batch_save, scan_finish, subfinder_hosts_mark_scanned, alerts_unseen_count, alerts_unsent, alert_mark_sent, alert_settings_get
        from scheduler.runner import _scan_lock, _scan_state
        from alerts.notifiers import AlertManager

        self.queue.join()
        for _ in self.threads:
            self.queue.put(None)
        for thread in self.threads:
            thread.join(timeout=5)
        with self.lock:
            batch = self.result_batch[:]
            self.result_batch.clear()
            done, total = self.done, self.total
            scanned = list(self.scanned_hosts)
        if batch:
            results_batch_save(self.scan_id, self.project_id, batch)
        subfinder_hosts_mark_scanned(self.project_id, scanned)
        publish("alert_update", {"unseen_count": alerts_unseen_count()})
        scan_finish(self.scan_id)
        finished_at = datetime.now(timezone.utc).isoformat()
        with _scan_lock:
            if self.scan_id in _scan_state:
                _scan_state[self.scan_id].update({"status": "done", "progress": total, "done": done, "total": total, "finished_at": finished_at})
        publish("scan_update", {"id": self.scan_id, "status": "done", "progress": total, "done": done, "total": total, "project_id": self.project_id, "source": "subfinder", "subfinder_job_id": self.job_id, "finished_at": finished_at})
        unsent = [a for a in alerts_unsent() if a["project_id"] == self.project_id and a.get("scan_id") == self.scan_id]
        if unsent and AlertManager(alert_settings_get()).dispatch(self.project.get("name") or f"project-{self.project_id[:8]}", unsent):
            for alert in unsent:
                alert_mark_sent(alert["id"])

def _start_subfinder_ssl_scan_async(project_id: str, hostnames: List[str], job_id: str) -> None:
    """Start certificate scans for discovered hosts without blocking enumeration results."""
    if not hostnames:
        return

    def worker():
        try:
            _ssl_scan_subfinder_hosts(project_id, hostnames, job_id)
        except Exception:
            # _ssl_scan_subfinder_hosts records the scan error; keep the
            # enumeration job completed so users can still inspect discoveries.
            log.exception("Background Subfinder SSL scan failed for project=%s job=%s", project_id, job_id)

    threading.Thread(
        target=worker,
        daemon=True,
        name=f"sf-ssl-{project_id[:8]}",
    ).start()


def _ssl_scan_subfinder_hosts(project_id: str, hostnames: List[str], job_id: str):
    """Run SSL checks on newly discovered subfinder hosts and save results."""
    from db.database import (
        scan_create, scan_finish, results_batch_save,
        subfinder_hosts_mark_scanned, alert_add, scan_progress, scan_update,
        alerts_unseen_count, alerts_unsent, alert_mark_sent, alert_settings_get,
        project_get
    )
    from core.ssl_checker import run_checker
    from scheduler.runner import (
        BATCH_SIZE, PROGRESS_UPDATE_EVERY, MAX_WORKERS, _scan_lock, _scan_state,
        _build_alert_from_result,
    )
    from alerts.notifiers import AlertManager

    if not hostnames:
        return

    total = len(hostnames)
    project = project_get(project_id) or {"name": f"project-{project_id[:8]}"}
    alert_settings = alert_settings_get()
    expiring_threshold = max(1, min(365, int(alert_settings.get("minimum_days_left") or 30)))
    scan = scan_create(project_id, total, by=f"subfinder:{job_id}")
    scan_id = scan["id"]

    with _scan_lock:
        _scan_state[scan_id] = {
            "id": scan_id, "status": "running", "progress": 0, "done": 0, "total": total,
            "project_id": project_id, "project_name": project.get("name") or f"project-{project_id[:8]}",
            "source": "subfinder", "subfinder_job_id": job_id,
            "started_at": datetime.now(timezone.utc).isoformat()
        }

    publish("scan_update", {"id": scan_id, "status": "running", "progress": 0, "done": 0, "total": total, "project_id": project_id, "source": "subfinder", "subfinder_job_id": job_id})

    result_batch = []
    done_count = [0]
    lock = threading.Lock()
    scanned_hosts = []

    def on_result(done, total_inner, r):
        hostname = r.get("hostname", "")
        scanned_hosts.append(hostname)

        alert = _build_alert_from_result(r, expiring_threshold)

        with lock:
            if alert:
                h, issue, detail, scope = alert
                alert_add(project_id, h, issue, f"[Subfinder] {detail}", scan_id, mismatch_scope=scope)
                publish("alert_update", {"unseen_count": alerts_unseen_count()})
            result_batch.append(r)
            done_count[0] += 1
            cur = done_count[0]
            if len(result_batch) >= BATCH_SIZE:
                batch = result_batch[:]
                result_batch.clear()
                results_batch_save(scan_id, project_id, batch)
            if cur % PROGRESS_UPDATE_EVERY == 0 or alert:
                scan_progress(scan_id, cur)
                payload = {"id": scan_id, "status": "running", "progress": cur, "done": cur, "total": total, "project_id": project_id, "source": "subfinder", "subfinder_job_id": job_id}
                with _scan_lock:
                    if scan_id in _scan_state:
                        _scan_state[scan_id].update({"progress": cur, "done": cur})
                publish("scan_update", payload)
            publish("scan_result", {"scan_id": scan_id, "project_id": project_id, "source": "subfinder", "row": r})

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

        publish("alert_update", {"unseen_count": alerts_unseen_count()})
        scan_finish(scan_id)
        subfinder_hosts_mark_scanned(project_id, scanned_hosts)

        finished_at = datetime.now(timezone.utc).isoformat()
        with _scan_lock:
            if scan_id in _scan_state:
                _scan_state[scan_id].update({"status": "done", "progress": total, "done": done_count[0], "finished_at": finished_at})
        publish("scan_update", {"id": scan_id, "status": "done", "progress": total, "done": done_count[0], "total": total, "project_id": project_id, "source": "subfinder", "subfinder_job_id": job_id, "finished_at": finished_at})

        unsent = [a for a in alerts_unsent() if a["project_id"] == project_id and a.get("scan_id") == scan_id]
        if unsent:
            delivered = AlertManager(alert_settings_get()).dispatch(project.get("name") or f"project-{project_id[:8]}", unsent)
            if delivered:
                for a in unsent:
                    alert_mark_sent(a["id"])
            else:
                log.warning("No remote alert channel accepted Subfinder SSL alerts for project '%s'; keeping alerts unsent for retry.", project.get("name"))
    except Exception as e:
        log.exception("Subfinder SSL scan failed for project=%s job=%s: %s", project_id, job_id, e)
        from db.database import scan_update
        finished_at = datetime.now(timezone.utc).isoformat()
        scan_update(scan_id, status="error", finished_at=finished_at)
        with _scan_lock:
            if scan_id in _scan_state:
                _scan_state[scan_id].update({"status": "error", "finished_at": finished_at})
        publish("scan_update", {"id": scan_id, "status": "error", "progress": done_count[0], "done": done_count[0], "total": total, "project_id": project_id, "source": "subfinder", "subfinder_job_id": job_id, "finished_at": finished_at, "error": str(e)})
        raise


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
        _sf_state[project_id] = {"status": "queued", "job_id": None, "new_count": 0}

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
