"""
subfinder/runner.py
Integrates ProjectDiscovery Subfinder with the SSL Sentinel pipeline.

How it works:
  1. Extracts root domains from project hosts and runs subfinder per root
  2. Parses stdout for discovered subdomains
  3. Deduplicates against previously stored hosts
  4. New hosts are written to subfinder_hosts table
  5. New hosts are immediately queued for SSL scanning
  6. Falls back to simulation mode if subfinder binary not found
"""

import gzip
import json
import logging
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import threading
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from core.observability import log_event

log = logging.getLogger(__name__)

SUBFINDER_BIN = shutil.which("subfinder") or "/usr/local/bin/subfinder"
_sf_lock = threading.Lock()
_sf_state = {}  # project_id -> {status, job_id, new_count}
_subfinder_all_flag_supported: Optional[bool] = None
MAX_CONCURRENT_SUBFINDER_PROJECTS = max(1, int(os.getenv("SUBFINDER_MAX_CONCURRENT_PROJECTS", "1")))
ACTIVE_SUBFINDER_STATUSES = {"queued", "running", "ssl_scanning"}

PASSIVE_SOURCE_TIMEOUT = max(5, int(os.getenv("SUBDOMAIN_PASSIVE_SOURCE_TIMEOUT", "20")))


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


def _fetch_passive_url(url: str, timeout: int) -> Tuple[str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "ssl-sentinel-subdomain-enumerator/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        content_type = resp.headers.get("content-type", "")
        body = resp.read(5_000_000).decode("utf-8", errors="replace")
    return content_type, body


def _passive_source_urls(root_domain: str) -> Dict[str, str]:
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


def _query_passive_source(source: str, url: str, root_domain: str, timeout: int) -> Tuple[str, List[str], Optional[str]]:
    try:
        content_type, body = _fetch_passive_url(url, timeout)
        hosts: Set[str] = set()
        if "json" in content_type.lower() or body.lstrip().startswith(("{", "[")):
            try:
                hosts.update(_extract_hosts_from_json(json.loads(body), root_domain))
            except json.JSONDecodeError:
                hosts.update(_candidate_hosts_from_text(body, root_domain))
        else:
            hosts.update(_candidate_hosts_from_text(body, root_domain))
        return source, sorted(hosts), None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return source, [], str(exc)[:500]


def enumerate_passive_subdomains(root_domain: str, timeout: int = PASSIVE_SOURCE_TIMEOUT) -> Dict[str, object]:
    """Query built-in passive sources and return in-scope subdomains.

    These sources require no API key, so a single scan can still enumerate from
    CT logs, passive DNS/intel APIs, scanners, and web archives even when the
    subfinder binary or provider config is unavailable. Slow or rate-limited
    sources are reported as warnings and do not fail the overall enumeration.
    """
    found_by_source: Dict[str, List[str]] = {}
    errors: Dict[str, str] = {}
    sources = _passive_source_urls(root_domain)
    workers = max(1, min(8, len(sources)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_query_passive_source, source, url, root_domain, timeout): source
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
    passive_command = "built-in passive sources: " + ", ".join(_passive_source_urls(root_domain).keys())
    command_str = " && ".join(filter(None, [" ".join(cmd), passive_command]))
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
            subfinder_stderr = "subfinder binary not found in PATH or /usr/local/bin/subfinder; used built-in passive sources"

        passive = enumerate_passive_subdomains(root_domain)
        passive_found = passive.get("found") or []
        found = sorted(set(subfinder_found) | set(passive_found))
        status = "done" if (subfinder_code in (0, None) or found) else "error"
        passive_summary = json.dumps({"sources": passive.get("sources", {}), "errors": passive.get("errors", {})}, separators=(",", ":"))
        stdout = "\n".join(filter(None, [subfinder_stdout, passive_summary]))
        stderr = subfinder_stderr
        if passive.get("errors"):
            stderr = "\n".join(filter(None, [stderr, "Passive source errors: " + json.dumps(passive.get("errors"), separators=(",", ":"))]))
        log.info("Subdomain enumeration finished root=%s subfinder_exit=%s discovered=%d", root_domain, subfinder_code, len(found))
        return {
            "root_domain": root_domain,
            "command": command_str,
            "status": status,
            "exit_code": subfinder_code,
            "stdout": stdout,
            "stderr": stderr,
            "found": found,
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
                _sf_state[project_id] = {"status": "done", "job_id": job_id, "new_count": 0}
            return job_id

        with _sf_lock:
            _sf_state[project_id]["new_count"] = new_count
            _sf_state[project_id]["status"] = "ssl_scanning" if scan_hosts else "done"

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
