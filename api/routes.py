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
    if not db.project_hosts(pid):
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


# ── Alerts ────────────────────────────────────────────────────────────────────

@api.get("/alerts")
def get_alerts():
    return ok(db.alerts_get())


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
    return ok(db.subfinder_raw_results_list(pid, limit=limit))


@api.get("/projects/<pid>/discoveries")
def project_discoveries(pid):
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(1000, max(50, int(request.args.get("per_page", 200))))
    search = (request.args.get("search", "") or "").strip()
    return ok(db.subfinder_discoveries(pid, page, per_page, search))


@api.put("/projects/<pid>/subfinder/toggle")
def toggle_subfinder(pid):
    p = db.project_get(pid)
    if not p: return err("Not found", 404)
    new_val = 0 if p.get("subfinder_enabled") else 1
    db.project_update(pid, subfinder_enabled=new_val)
    return ok({"subfinder_enabled": new_val})


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
