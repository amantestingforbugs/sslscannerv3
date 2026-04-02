"""
api/routes.py — All REST endpoints + SSE stream for real-time UI updates.
Fixes:
  - Alert clear now pushes SSE event so counter resets without page refresh
  - All heavy ops are async — create_project is instant
  - Added /api/sse for real-time push to browser
  - Subfinder CRUD endpoints
"""

import json
import queue
import threading
import time
import logging
import subprocess
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, Response, stream_with_context

import db.database as db
from core.ssl_checker import parse_hosts_file
from core.observability import subscribe, get_logs
from scheduler.runner import run_project_scan_async, get_scan_state, list_active_scans

log = logging.getLogger(__name__)
api = Blueprint("api", __name__, url_prefix="/api")

# ── SSE broadcast bus ─────────────────────────────────────────────────────────
# Each connected browser gets its own queue. Events pushed here reach all clients.
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()
_openssl_threads: dict[str, threading.Thread] = {}
_openssl_status: dict[str, dict] = {}
_openssl_lock = threading.Lock()
_quick_scan_threads: dict[str, threading.Thread] = {}
_quick_scan_state: dict[str, dict] = {}
_quick_scan_lock = threading.Lock()


def broadcast(event: str, data: dict):
    """Push an event to all connected SSE clients."""
    msg = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


def _handle_observability_event(evt: dict):
    event_name = evt.get("event")
    if event_name:
        payload = {k: v for k, v in evt.items() if k != "event"}
        broadcast(event_name, payload)


subscribe(_handle_observability_event)


# ── Helpers ───────────────────────────────────────────────────────────────────

def ok(data=None, **kw):
    p = {"ok": True}
    if data is not None: p["data"] = data
    p.update(kw)
    return jsonify(p)


def err(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code


def _normalize_hostname(raw: str) -> str:
    v = (raw or "").strip().lower()
    if not v:
        return ""
    if "://" in v:
        try:
            v = (urlparse(v).hostname or "").strip().lower()
        except Exception:
            v = ""
    if ":" in v:
        v = v.split(":", 1)[0]
    return v.strip(".")


def _run_openssl_subject(hostname: str, timeout: int = 20) -> dict:
    cmd = ["openssl", "s_client", "-connect", f"{hostname}:443"]
    try:
        run = subprocess.run(
            cmd,
            input="",
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        lines = [ln.strip() for ln in (run.stdout or "").splitlines() if "subject" in ln.lower()]
        subject = lines[0] if lines else ""
        return {
            "hostname": hostname,
            "subject": subject or "subject not found",
            "status": "ok" if subject else "no_subject",
            "exit_code": run.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"hostname": hostname, "subject": "", "status": "timeout", "error": f"timeout after {timeout}s"}
    except FileNotFoundError:
        return {"hostname": hostname, "subject": "", "status": "error", "error": "openssl binary not found"}
    except Exception as e:
        return {"hostname": hostname, "subject": "", "status": "error", "error": str(e)}


def _collect_openssl_hosts(pid: str) -> list[str]:
    base_hosts = {_normalize_hostname(h) for h in db.project_hosts(pid)}
    sf_hosts = {
        _normalize_hostname(r["hostname"])
        for r in db.x("SELECT hostname FROM subfinder_hosts WHERE project_id=?", (pid,)).fetchall()
    }
    return sorted({h for h in (base_hosts | sf_hosts) if h})


def _start_quick_scan(hosts: list[str]) -> str:
    sid = db.uid()
    with _quick_scan_lock:
        _quick_scan_state[sid] = {
            "id": sid,
            "status": "running",
            "source": "quick_scan",
            "total": len(hosts),
            "done": 0,
            "ok": 0,
            "mismatches": 0,
            "expired": 0,
            "expiring": 0,
            "errors": 0,
            "hosts": hosts,
            "rows": [],
            "started_at": db.now(),
            "finished_at": None,
        }
    th = threading.Thread(target=_quick_scan_worker, args=(sid,), daemon=True, name=f"quick-scan-{sid[:8]}")
    with _quick_scan_lock:
        _quick_scan_threads[sid] = th
    th.start()
    return sid


def _quick_scan_worker(sid: str):
    from core.ssl_checker import run_checker

    with _quick_scan_lock:
        state = _quick_scan_state.get(sid)
        hosts = list(state.get("hosts") or []) if state else []
    if not hosts:
        with _quick_scan_lock:
            if sid in _quick_scan_state:
                _quick_scan_state[sid]["status"] = "error"
                _quick_scan_state[sid]["finished_at"] = db.now()
        return

    def _on_result(done: int, total: int, row: dict):
        row = dict(row or {})
        row.setdefault("hostname", "")
        row.setdefault("cn", "")
        row.setdefault("issuer", "")
        row.setdefault("expiry", "")
        row.setdefault("days_left", None)
        row["is_expiring"] = bool(row.get("is_expiring_soon"))
        with _quick_scan_lock:
            state = _quick_scan_state.get(sid)
            if not state:
                return
            state["rows"].append(row)
            state["done"] = done
            state["ok"] += 1 if row.get("is_ok") else 0
            state["mismatches"] += 1 if row.get("is_mismatch") else 0
            state["expired"] += 1 if row.get("is_expired") else 0
            state["expiring"] += 1 if row.get("is_expiring_soon") else 0
            state["errors"] += 1 if row.get("error") else 0
            payload = {
                "id": sid,
                "status": "running",
                "total": total,
                "done": done,
                "ok": state["ok"],
                "mismatches": state["mismatches"],
                "expired": state["expired"],
                "expiring": state["expiring"],
                "errors": state["errors"],
            }
        broadcast("quick_scan_row", {"scan_id": sid, "row": row})
        broadcast("quick_scan_update", payload)

    try:
        run_checker(hosts, progress_callback=_on_result, collect_results=False)
        with _quick_scan_lock:
            state = _quick_scan_state.get(sid)
            if state:
                state["status"] = "done"
                state["finished_at"] = db.now()
                state["hosts"] = []
                payload = {
                    "id": sid,
                    "status": "done",
                    "total": state["total"],
                    "done": state["done"],
                    "ok": state["ok"],
                    "mismatches": state["mismatches"],
                    "expired": state["expired"],
                    "expiring": state["expiring"],
                    "errors": state["errors"],
                    "finished_at": state["finished_at"],
                }
        broadcast("quick_scan_update", payload)
    except Exception as e:
        with _quick_scan_lock:
            state = _quick_scan_state.get(sid)
            if state:
                state["status"] = "error"
                state["error"] = str(e)
                state["finished_at"] = db.now()
                state["hosts"] = []
                payload = {
                    "id": sid,
                    "status": "error",
                    "error": str(e),
                    "total": state["total"],
                    "done": state["done"],
                }
        broadcast("quick_scan_update", payload)


def _start_openssl_worker(pid: str, source: str = "manual") -> bool:
    with _openssl_lock:
        existing = _openssl_threads.get(pid)
        if existing and existing.is_alive():
            return False
        _openssl_status[pid] = {
            "status": "running",
            "source": source,
            "started_at": time.time(),
            "last_tick": time.time(),
            "processed_total": 0,
            "new_hosts_scanned": 0,
        }
        th = threading.Thread(target=_openssl_worker_loop, args=(pid, source), daemon=True, name=f"openssl-{pid[:8]}")
        _openssl_threads[pid] = th
        th.start()
        return True


def _openssl_worker_loop(pid: str, source: str):
    try:
        while True:
            if not db.project_get(pid):
                break
            known = {r["hostname"] for r in db.openssl_results_list(pid, limit=5000)}
            hosts = _collect_openssl_hosts(pid)
            pending = [h for h in hosts if h not in known]

            with _openssl_lock:
                if pid in _openssl_status:
                    _openssl_status[pid]["last_tick"] = time.time()

            if not pending:
                broadcast("openssl_status", {"project_id": pid, "status": "idle_waiting", "tracked_hosts": len(hosts)})
                time.sleep(10)
                continue

            rows = []
            for hostname in pending:
                row = _run_openssl_subject(hostname)
                rows.append(row)
                db.openssl_results_upsert_batch(pid, [row], source=source)
                with _openssl_lock:
                    if pid in _openssl_status:
                        _openssl_status[pid]["processed_total"] += 1
                        _openssl_status[pid]["new_hosts_scanned"] += 1
                broadcast("openssl_row", {"project_id": pid, "row": row})

            broadcast("openssl_status", {
                "project_id": pid,
                "status": "running",
                "processed": len(rows),
                "pending_after": 0,
                "tracked_hosts": len(hosts),
            })
            time.sleep(2)
    finally:
        with _openssl_lock:
            if pid in _openssl_status:
                _openssl_status[pid]["status"] = "stopped"
        broadcast("openssl_status", {"project_id": pid, "status": "stopped"})


# ── SSE stream ────────────────────────────────────────────────────────────────

@api.get("/sse")
def sse_stream():
    """
    Server-Sent Events endpoint. Browser connects once and receives live events:
      - alert_update: {unseen_count}
      - scan_update:  {scan_id, progress, total, status}
      - stats_update: {mismatches, expired, ...}
    """
    q = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_clients.append(q)

    def generate():
        # Send initial heartbeat
        yield f"event: connected\ndata: {{}}\n\n"
        try:
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield msg
                except queue.Empty:
                    # Heartbeat to keep connection alive (Railway times out at 30s)
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        }
    )


# ── Projects ──────────────────────────────────────────────────────────────────

@api.get("/projects")
def list_projects():
    projects = db.project_list()
    for p in projects:
        p["latest_scan"] = db.scan_latest(p["id"])
    return ok(projects)


@api.post("/projects")
def create_project():
    d = request.json or {}
    name = (d.get("name") or "").strip()
    if not name:
        return err("name is required")
    if db.project_get_by_name(name):
        return err("A project with that name already exists")
    p = db.project_create(
        name,
        d.get("description", ""),
        int(d.get("scan_interval", 60)),
        int(d.get("subfinder_interval", 30)),
    )
    broadcast("project_created", {"id": p["id"], "name": p["name"]})
    return ok(p)


@api.get("/projects/<pid>")
def get_project(pid):
    p = db.project_get(pid)
    if not p: return err("Not found", 404)
    p["latest_scan"] = db.scan_latest(pid)
    return ok(p)


@api.put("/projects/<pid>")
def update_project(pid):
    d = request.json or {}
    allowed = {"name","description","scan_interval_minutes","subfinder_interval_minutes",
               "subfinder_enabled","enabled"}
    kw = {k: v for k, v in d.items() if k in allowed}
    db.project_update(pid, **kw)
    return ok(db.project_get(pid))


@api.delete("/projects/<pid>")
def delete_project(pid):
    db.project_delete(pid)
    broadcast("project_deleted", {"id": pid})
    return ok()


@api.post("/projects/<pid>/hosts")
def upload_hosts(pid):
    if not db.project_get(pid):
        return err("Project not found", 404)
    if "file" in request.files:
        content = request.files["file"].read().decode("utf-8", errors="ignore")
    else:
        content = (request.json or {}).get("hosts", "") or (request.data or b"").decode()
    hosts = parse_hosts_file(content)
    if not hosts:
        return err("No valid hostnames found")
    db.project_save_hosts(pid, hosts)
    return ok({"count": len(hosts)})


@api.get("/projects/<pid>/hosts")
def get_hosts(pid):
    return ok(db.project_hosts(pid))


# ── Scans ─────────────────────────────────────────────────────────────────────

@api.post("/projects/<pid>/scan")
def trigger_scan(pid):
    p = db.project_get(pid)
    if not p: return err("Project not found", 404)
    if int(p.get("host_count") or 0) <= 0:
        return err("Upload a host list first")
    if not run_project_scan_async(pid, triggered_by="manual"):
        return err("A scan is already running for this project")
    return ok({"message": "Scan started"})


@api.get("/projects/<pid>/scans")
def list_scans(pid):
    return ok(db.scan_list(pid))


@api.get("/scans/<sid>")
def get_scan(sid):
    s = db.scan_get(sid)
    if not s: return err("Not found", 404)
    live = get_scan_state(sid)
    if live: s["live_progress"] = live.get("progress", 0)
    return ok(s)


@api.get("/scans/<sid>/results")
def get_results(sid):
    flt = request.args.get("filter", "all")
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(1000, max(50, int(request.args.get("per_page", 500))))
    return ok(db.results_get(sid, flt, page, per_page))


@api.get("/active-scans")
def active_scans():
    return ok(list_active_scans())


@api.post("/quick-scan")
def start_quick_scan():
    d = request.json or {}
    hosts_raw = d.get("hosts", "") or ""
    hosts = parse_hosts_file(hosts_raw)
    hosts = sorted({_normalize_hostname(h) for h in hosts if _normalize_hostname(h)})
    if not hosts:
        return err("Paste at least one valid hostname")
    if len(hosts) > 5000:
        return err("Quick scan supports up to 5000 hosts at once")
    sid = _start_quick_scan(hosts)
    return ok({"scan_id": sid, "total": len(hosts), "status": "running"})


@api.get("/quick-scan/<sid>")
def quick_scan_status(sid):
    with _quick_scan_lock:
        state = dict(_quick_scan_state.get(sid) or {})
    if not state:
        return err("Quick scan not found", 404)
    rows = state.get("rows", [])
    state["rows_total"] = len(rows)
    # Keep status payload tiny so polling remains fast even for large scans.
    state.pop("rows", None)
    state.pop("hosts", None)
    return ok(state)


# ── Alerts ────────────────────────────────────────────────────────────────────

@api.get("/alerts")
def get_alerts():
    search = (request.args.get("search", "") or "").strip()
    mismatch = (request.args.get("mismatch_scope", "all") or "all").strip()
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(1000, max(50, int(request.args.get("per_page", 200))))
    return ok(db.alerts_get(search=search, mismatch_scope=mismatch, page=page, per_page=per_page))


@api.post("/alerts/<aid>/read")
def mark_one_seen(aid):
    db.alert_mark_seen(aid)
    broadcast("alert_update", {"unseen_count": db.alerts_unseen_count()})
    return ok()


@api.post("/alerts/seen")
def mark_seen():
    db.alerts_mark_all_seen()
    # Push SSE so badge resets instantly in all open tabs
    broadcast("alert_update", {"unseen_count": 0})
    return ok()


@api.post("/alerts/clear")
def clear_alerts():
    db.alerts_clear()
    # Push SSE — this is what was missing causing the stale counter bug
    broadcast("alert_update", {"unseen_count": 0})
    return ok()


# ── Stats ─────────────────────────────────────────────────────────────────────

@api.get("/stats")
def global_stats():
    return ok(db.stats_global())


@api.get("/logs")
def list_logs():
    limit = min(1000, max(20, int(request.args.get("limit", 200))))
    return ok(get_logs(limit))


# ── Subfinder ─────────────────────────────────────────────────────────────────

@api.post("/projects/<pid>/subfinder/run")
def run_subfinder(pid):
    from subfinder.runner import run_subfinder_async, subfinder_available
    if not pid or pid in {"undefined", "null"}:
        return err("Please select a project before running scan")
    p = db.project_get(pid)
    if not p: return err("Project not found", 404)
    if not db.project_hosts(pid):
        return err("Add a host list first so subfinder knows which root domains to enumerate")
    started = run_subfinder_async(pid, triggered_by="manual")
    if not started:
        return err("Subfinder already running for this project")
    return ok({
        "message": "Subfinder started",
        "binary_found": subfinder_available()
    })


@api.get("/projects/<pid>/subfinder/status")
def subfinder_status(pid):
    from subfinder.runner import get_sf_state, subfinder_available
    return ok({
        "state": get_sf_state(pid),
        "binary_available": subfinder_available(),
        "jobs": db.subfinder_jobs_list(pid, limit=10)
    })


@api.get("/projects/<pid>/subfinder/hosts")
def subfinder_hosts(pid):
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(1000, max(50, int(request.args.get("per_page", 500))))
    return ok(db.subfinder_hosts_list(pid, page, per_page))


@api.get("/projects/<pid>/subfinder/raw-results")
def subfinder_raw_results(pid):
    limit = min(100, max(1, int(request.args.get("limit", 20))))
    preview_chars = min(12000, max(500, int(request.args.get("preview_chars", 4000))))
    return ok(db.subfinder_raw_results_list(pid, limit=limit, preview_chars=preview_chars))


@api.get("/projects/<pid>/discoveries")
def project_discoveries(pid):
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(1000, max(50, int(request.args.get("per_page", 200))))
    search = (request.args.get("search", "") or "").strip()
    mode = (request.args.get("mode", "all") or "all").strip().lower()
    return ok(db.subfinder_discoveries(pid, page, per_page, search, mode=mode))


@api.put("/projects/<pid>/subfinder/toggle")
def toggle_subfinder(pid):
    p = db.project_get(pid)
    if not p: return err("Not found", 404)
    new_val = 0 if p.get("subfinder_enabled") else 1
    db.project_update(pid, subfinder_enabled=new_val)
    return ok({"subfinder_enabled": new_val})


@api.post("/projects/<pid>/openssl")
def openssl_subjects(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)

    # Run a fresh subfinder pass first so newly discovered subdomains are included.
    subfinder_job_id = None
    subfinder_error = ""
    try:
        from subfinder.runner import run_subfinder_for_project
        subfinder_job_id = run_subfinder_for_project(pid, triggered_by="manual:openssl")
    except Exception as e:
        subfinder_error = str(e)

    hosts = _collect_openssl_hosts(pid)
    if not hosts:
        return err("No hosts found. Upload project hosts first.", 400)

    rows = [_run_openssl_subject(h) for h in hosts]
    db.openssl_results_upsert_batch(pid, rows, source="manual")
    return ok({
        "project_id": pid,
        "project_name": p["name"],
        "hosts_total": len(hosts),
        "subfinder_job_id": subfinder_job_id,
        "subfinder_error": subfinder_error,
        "command_template": "openssl s_client -connect HOSTNAME:443 </dev/null 2>/dev/null | grep subject",
        "rows": rows,
    })


@api.get("/projects/<pid>/openssl")
def openssl_subjects_list(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)
    limit = min(5000, max(50, int(request.args.get("limit", 2000))))
    search = (request.args.get("search", "") or "").strip()
    rows = db.openssl_results_list(pid, search=search, limit=limit)
    with _openssl_lock:
        status = dict(_openssl_status.get(pid) or {"status": "idle"})
    return ok({
        "project_id": pid,
        "project_name": p["name"],
        "rows": rows,
        "rows_total": len(rows),
        "tracked_hosts": len(_collect_openssl_hosts(pid)),
        "worker": status,
    })


@api.post("/projects/<pid>/openssl/start")
def openssl_subjects_start(pid):
    p = db.project_get(pid)
    if not p:
        return err("Project not found", 404)
    started = _start_openssl_worker(pid, source="continuous")
    return ok({
        "project_id": pid,
        "project_name": p["name"],
        "started": started,
        "message": "OpenSSL continuous scan started" if started else "OpenSSL continuous scan already running",
    })


# ── Background SSE broadcaster for scan progress ───────────────────────────────

def _scan_broadcast_loop():
    """Pushes scan progress and stats via SSE every 3 seconds if anyone is scanning."""
    while True:
        try:
            active = list_active_scans()
            if active:
                for s in active:
                    broadcast("scan_update", s)
                # Also push updated stats
                broadcast("stats_update", db.stats_global())
                # Push alert count
                broadcast("alert_update", {"unseen_count": db.alerts_unseen_count()})
        except Exception:
            pass
        time.sleep(3)


threading.Thread(target=_scan_broadcast_loop, daemon=True, name="sse-broadcaster").start()
