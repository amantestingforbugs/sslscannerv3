"""
scheduler/runner.py — Background SSL scan scheduler.
Exports BATCH_SIZE and PROGRESS_UPDATE_EVERY for use by subfinder module.
"""

import os
import threading, time, logging
from datetime import datetime, timezone
from typing import Dict, Optional
from core.observability import log_event, publish

log = logging.getLogger(__name__)

# ── Shared constants (used by subfinder module too) ───────────────────────────
BATCH_SIZE = 500
PROGRESS_UPDATE_EVERY = 500
MAX_WORKERS = int(os.getenv("SSL_MAX_WORKERS", "200"))

# ── In-memory scan state (shared with subfinder via import) ───────────────────
_scan_state: Dict[str, Dict] = {}
_scan_lock = threading.Lock()
_scan_controls: Dict[str, Dict[str, threading.Event]] = {}


def _now():
    return datetime.now(timezone.utc).isoformat()


def get_scan_state(sid: str) -> Optional[Dict]:
    with _scan_lock:
        return _scan_state.get(sid)


def list_active_scans() -> list:
    with _scan_lock:
        return [v.copy() for v in _scan_state.values() if v.get("status") in {"running", "paused"}]


def pause_scan(sid: str) -> bool:
    with _scan_lock:
        state = _scan_state.get(sid)
        controls = _scan_controls.get(sid)
        if not state or state.get("status") != "running" or not controls:
            return False
        controls["pause"].set()
        state["status"] = "paused"
    return True


def resume_scan(sid: str) -> bool:
    with _scan_lock:
        state = _scan_state.get(sid)
        controls = _scan_controls.get(sid)
        if not state or state.get("status") != "paused" or not controls:
            return False
        controls["pause"].clear()
        state["status"] = "running"
    return True


def stop_scan(sid: str) -> bool:
    with _scan_lock:
        state = _scan_state.get(sid)
        controls = _scan_controls.get(sid)
        if not state or state.get("status") not in {"running", "paused"} or not controls:
            return False
        controls["stop"].set()
        controls["pause"].clear()
        state["status"] = "stopping"
    return True


def run_project_scan(project_id: str, triggered_by: str = "manual") -> Optional[str]:
    from db.database import (
        project_get, project_hosts, scan_create, results_batch_save,
        scan_finish, scan_update, scan_progress,
        alert_add, alerts_unsent, alert_mark_sent, alerts_unseen_count, alert_settings_get
    )
    from core.ssl_checker import run_checker
    from alerts.notifiers import AlertManager

    project = project_get(project_id)
    if not project:
        return None
    hosts = project_hosts(project_id)
    if not hosts:
        return None

    total = len(hosts)
    alert_settings = alert_settings_get()
    expiring_threshold = max(1, min(365, int(alert_settings.get("minimum_days_left") or 30)))
    log.info("Scan start: '%s' (%d hosts) [%s]", project["name"], total, triggered_by)
    log_event("ssl_scan", "info", "Scan started", project_id=project_id, total=total, triggered_by=triggered_by, status="running")

    scan = scan_create(project_id, total, triggered_by)
    sid = scan["id"]

    with _scan_lock:
        _scan_state[sid] = {
            "status": "running", "progress": 0, "total": total,
            "project_id": project_id, "project_name": project["name"],
            "started_at": _now(),
        }
        _scan_controls[sid] = {"pause": threading.Event(), "stop": threading.Event()}

    result_batch, alert_batch, done_count = [], [], [0]
    lock = threading.Lock()

    def on_result(done, total_inner, r):
        hostname = r.get("hostname", "")
        alert = None
        days_left = r.get("days_left")
        is_expiring_by_setting = isinstance(days_left, int) and 0 <= days_left <= expiring_threshold
        if is_expiring_by_setting:
            r["is_expiring_soon"] = True
        elif r.get("is_expiring_soon") and isinstance(days_left, int) and days_left > expiring_threshold:
            r["is_expiring_soon"] = False
        if r.get("is_ok") and is_expiring_by_setting:
            r["is_ok"] = False
        elif r.get("is_ok") and isinstance(days_left, int) and days_left <= expiring_threshold:
            r["is_ok"] = False

        if r.get("is_mismatch") and not r.get("error"):
            mismatch_scope = "same_domain" if r.get("same_base") else "different_domain"
            alert = (hostname, "SSL Mismatch", f"CN '{r.get('cn','?')}' ≠ hostname", mismatch_scope)
        elif r.get("is_expired") and not r.get("error"):
            alert = (hostname, "Expired", f"Expired {r.get('expiry','?')}", "")
        elif is_expiring_by_setting and not r.get("error"):
            alert = (hostname, "Expiring Soon", f"Expires {r.get('expiry','?')} ({r.get('days_left')}d)", "")
        elif r.get("error"):
            alert = (hostname, "Scan Error", r.get("error") or "Unknown TLS error", "")
        with lock:
            if alert:
                alert_batch.append(alert)
            result_batch.append(r)
            done_count[0] += 1
            cur = done_count[0]
            if len(result_batch) >= BATCH_SIZE:
                batch = result_batch[:]
                result_batch.clear()
                results_batch_save(sid, project_id, batch)
                for h, issue, detail, scope in alert_batch:
                    alert_add(project_id, h, issue, detail, sid, mismatch_scope=scope)
                alert_batch.clear()
            if cur % PROGRESS_UPDATE_EVERY == 0:
                scan_progress(sid, cur)
                with _scan_lock:
                    if sid in _scan_state:
                        _scan_state[sid]["progress"] = cur

    try:
        run_checker(
            hosts,
            max_workers=MAX_WORKERS,
            progress_callback=on_result,
            collect_results=False,  # avoid storing millions of in-memory results
            pause_event=_scan_controls[sid]["pause"],
            stop_event=_scan_controls[sid]["stop"],
        )

        with _scan_lock:
            controls = _scan_controls.get(sid)
            was_stopped = bool(controls and controls["stop"].is_set())

        with lock:
            if result_batch:
                results_batch_save(sid, project_id, result_batch)
            for h, issue, detail, scope in alert_batch:
                alert_add(project_id, h, issue, detail, sid, mismatch_scope=scope)
        publish("alert_update", {"unseen_count": alerts_unseen_count()})
        if was_stopped:
            done = done_count[0]
            scan_update(sid, status="stopped", finished_at=_now(), done=done)
            with _scan_lock:
                if sid in _scan_state:
                    _scan_state[sid].update({"status": "stopped", "progress": done, "finished_at": _now(), "done": done})
            log_event("ssl_scan", "warning", "Scan stopped by user", project_id=project_id, scan_id=sid, total=total, done=done, status="stopped")
        else:
            scan_finish(sid)
            log_event("ssl_scan", "info", "Scan finished", project_id=project_id, scan_id=sid, total=total, status="idle")
            with _scan_lock:
                if sid in _scan_state:
                    _scan_state[sid].update({"status": "done", "progress": total, "finished_at": _now(), "done": total})

        # Send Telegram
        unsent = [a for a in alerts_unsent() if a["project_id"] == project_id]
        if unsent:
            delivered = AlertManager(alert_settings_get()).dispatch(project["name"], unsent)
            if not delivered:
                log.warning("No remote alert channel accepted alerts for project '%s'; keeping alerts unsent for retry.", project["name"])
                return sid
            for a in unsent:
                alert_mark_sent(a["id"])

        log.info("Scan done: '%s'", project["name"])
        return sid

    except Exception as e:
        log.exception("Scan failed for '%s': %s", project["name"], e)
        log_event("ssl_scan", "error", f"Scan failed: {e}", project_id=project_id, scan_id=sid, status="failed")
        scan_update(sid, status="error")
        with _scan_lock:
            if sid in _scan_state:
                _scan_state[sid]["status"] = "error"
        return None
    finally:
        with _scan_lock:
            _scan_controls.pop(sid, None)


def run_project_scan_async(project_id: str, triggered_by: str = "manual") -> bool:
    with _scan_lock:
        for s in _scan_state.values():
            if s.get("project_id") == project_id and s.get("status") in {"running", "paused", "stopping"}:
                return False
    threading.Thread(target=run_project_scan, args=(project_id, triggered_by),
                     daemon=True, name=f"scan-{project_id[:8]}").start()
    return True


class ContinuousScheduler:
    def __init__(self):
        self._thread = None
        self._stop = threading.Event()
        self._last_run: Dict[str, float] = {}

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ssl-scheduler")
        self._thread.start()
        log.info("SSL scheduler started")

    def stop(self): self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            try: self._tick()
            except Exception as e: log.exception("Scheduler error: %s", e)
            self._stop.wait(60)

    def _tick(self):
        from db.database import project_list
        now_ts = time.time()
        for p in project_list():
            if not p.get("enabled"):
                continue
            pid = p["id"]
            interval_s = p.get("scan_interval_minutes", 60) * 60
            if now_ts - self._last_run.get(pid, 0) >= interval_s:
                self._last_run[pid] = now_ts
                run_project_scan_async(pid, triggered_by="scheduler")


_scheduler = ContinuousScheduler()
def start_scheduler(): _scheduler.start()
def stop_scheduler():  _scheduler.stop()
