"""
subfinder/runner.py
Integrates ProjectDiscovery Subfinder with the SSL Sentinel pipeline.

How it works:
  1. Runs `subfinder -d domain1,domain2 -silent` as a subprocess
  2. Parses stdout for discovered subdomains
  3. Deduplicates against previously stored hosts
  4. New hosts are written to subfinder_hosts table
  5. New hosts are immediately queued for SSL scanning
  6. Falls back to simulation mode if subfinder binary not found
"""

import subprocess
import shutil
import threading
import time
import logging
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)

SUBFINDER_BIN = shutil.which("subfinder") or "/usr/local/bin/subfinder"
_sf_lock = threading.Lock()
_sf_state = {}  # project_id -> {status, job_id, new_count}


def subfinder_available() -> bool:
    return Path(SUBFINDER_BIN).exists() if SUBFINDER_BIN else False


def _run_subfinder_process(domains: List[str], timeout: int = 300) -> List[str]:
    """
    Execute subfinder binary and return discovered hostnames.
    Returns empty list if binary not found or times out.
    """
    if not subfinder_available():
        log.warning("subfinder binary not found at %s. Install from: "
                    "https://github.com/projectdiscovery/subfinder", SUBFINDER_BIN)
        return []

    domain_str = ",".join(domains)
    cmd = [SUBFINDER_BIN, "-d", domain_str, "-silent", "-all", "-timeout", "30"]

    try:
        log.info("Running subfinder on: %s", domain_str)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        found = [line.strip() for line in result.stdout.splitlines()
                 if line.strip() and "." in line.strip()]
        log.info("Subfinder found %d subdomains for %s", len(found), domain_str)
        return found
    except subprocess.TimeoutExpired:
        log.error("Subfinder timed out for domains: %s", domain_str)
        return []
    except Exception as e:
        log.exception("Subfinder execution error: %s", e)
        return []


def _extract_root_domains(hosts: List[str]) -> List[str]:
    """Extract unique root domains from a host list for subfinder to enumerate."""
    try:
        import tldextract
        domains = set()
        for h in hosts:
            e = tldextract.extract(h)
            if e.domain and e.suffix:
                domains.add(f"{e.domain}.{e.suffix}")
        return list(domains)
    except ImportError:
        # Fallback: take last two parts
        domains = set()
        for h in hosts:
            parts = h.split(".")
            if len(parts) >= 2:
                domains.add(".".join(parts[-2:]))
        return list(domains)


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
        subfinder_job_error, subfinder_hosts_add_batch, subfinder_hosts_new_unsscanned,
        subfinder_hosts_mark_scanned, results_batch_save, scan_create, scan_finish,
        alert_add, project_update
    )
    from core.ssl_checker import run_checker
    from scheduler.runner import BATCH_SIZE, PROGRESS_UPDATE_EVERY, _scan_lock, _scan_state

    project = project_get(project_id)
    if not project:
        return None

    hosts = project_hosts(project_id)
    if not hosts:
        log.warning("Subfinder: project '%s' has no base hosts", project["name"])
        return None

    root_domains = _extract_root_domains(hosts)
    if not root_domains:
        return None

    log.info("Subfinder starting for '%s' — domains: %s", project["name"], root_domains)

    domain_input = ",".join(root_domains)
    job_id = subfinder_job_create(project_id, domain_input, triggered_by)

    with _sf_lock:
        _sf_state[project_id] = {"status": "running", "job_id": job_id, "new_count": 0}

    try:
        # Run subfinder
        discovered = _run_subfinder_process(root_domains)

        if not discovered:
            subfinder_job_finish(job_id, 0, 0)
            with _sf_lock:
                _sf_state[project_id] = {"status": "done", "job_id": job_id, "new_count": 0}
            return job_id

        # Store new hosts, get count of genuinely new ones
        new_count = subfinder_hosts_add_batch(project_id, discovered)
        subfinder_job_finish(job_id, new_count, len(discovered))

        with _sf_lock:
            _sf_state[project_id]["new_count"] = new_count
            _sf_state[project_id]["status"] = "ssl_scanning"

        log.info("Subfinder: %d new hosts for '%s', triggering SSL scan",
                 new_count, project["name"])

        # SSL scan all unscanned subfinder hosts
        unscanned = subfinder_hosts_new_unsscanned(project_id)
        if unscanned:
            _ssl_scan_subfinder_hosts(project_id, unscanned, job_id)

        with _sf_lock:
            _sf_state[project_id]["status"] = "done"

        return job_id

    except Exception as e:
        log.exception("Subfinder pipeline error for '%s': %s", project["name"], e)
        subfinder_job_error(job_id, str(e))
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
    from scheduler.runner import BATCH_SIZE, PROGRESS_UPDATE_EVERY, _scan_lock, _scan_state

    if not hostnames:
        return

    total = len(hostnames)
    scan = scan_create(project_id, total, by=f"subfinder:{job_id}")
    scan_id = scan["id"]

    with _scan_lock:
        _scan_state[scan_id] = {
            "status": "running", "progress": 0, "total": total,
            "project_id": project_id, "project_name": f"subfinder-{project_id[:8]}",
            "started_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc).isoformat()
        }

    result_batch = []
    done_count = [0]
    lock = threading.Lock()
    scanned_hosts = []

    def on_result(done, total_inner, r):
        hostname = r.get("hostname", "")
        scanned_hosts.append(hostname)

        if r.get("is_mismatch") and not r.get("error"):
            alert_add(project_id, hostname, "SSL Mismatch",
                      f"[Subfinder] CN '{r.get('cn','?')}' ≠ hostname", scan_id)
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

    run_checker(hostnames, max_workers=200, progress_callback=on_result)

    with lock:
        if result_batch:
            results_batch_save(scan_id, project_id, result_batch)

    scan_finish(scan_id)
    subfinder_hosts_mark_scanned(project_id, scanned_hosts)

    with _scan_lock:
        if scan_id in _scan_state:
            _scan_state[scan_id]["status"] = "done"
            _scan_state[scan_id]["progress"] = total


def run_subfinder_async(project_id: str, triggered_by: str = "manual") -> bool:
    """Start subfinder pipeline in background thread. Returns False if already running."""
    with _sf_lock:
        if _sf_state.get(project_id, {}).get("status") in ("running", "ssl_scanning"):
            return False

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
            interval_s = p.get("subfinder_interval_minutes", 30) * 60
            if now_ts - self._last_run.get(pid, 0) >= interval_s:
                self._last_run[pid] = now_ts
                run_subfinder_async(pid, triggered_by="scheduler")


_sf_scheduler = SubfinderScheduler()


def start_subfinder_scheduler():
    _sf_scheduler.start()

def stop_subfinder_scheduler():
    _sf_scheduler.stop()
