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
import csv
import io
import os
import signal
import subprocess
from urllib.parse import urlparse
from flask import Blueprint, request, jsonify, Response, stream_with_context

import db.database as db
from core.ssl_checker import parse_hosts_file
from core.observability import subscribe, get_logs
from scheduler.runner import (
    run_project_scan_async,
    get_scan_state,
    list_active_scans,
    pause_scan,
    resume_scan,
    stop_scan,
)

log = logging.getLogger(__name__)
api = Blueprint("api", __name__, url_prefix="/api")

# ── SSE broadcast bus ─────────────────────────────────────────────────────────
# Each connected browser gets its own queue. Events pushed here reach all clients.
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()
_quick_scan_threads: dict[str, threading.Thread] = {}
_quick_scan_state: dict[str, dict] = {}
_quick_scan_lock = threading.Lock()
QUICK_SCAN_ROWS_BUFFER = 500

_subdomain_tool_lock = threading.Lock()
_subdomain_tool_state: dict[str, dict] = {}
_subdomain_tool_threads: dict[str, threading.Thread] = {}
_subdomain_tool_processes: dict[str, subprocess.Popen] = {}
ACTIVE_SUBDOMAIN_TOOL_STATUSES = {"queued", "running", "paused", "stopping"}


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



def _normalize_domain(raw: str) -> str:
    host = _normalize_hostname(raw)
    if not host or "." not in host:
        return ""
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")
    if any(ch not in allowed for ch in host) or ".." in host:
        return ""
    return host


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
            "rows_total": 0,
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
            state["rows_total"] = int(state.get("rows_total") or 0) + 1
            if len(state["rows"]) > QUICK_SCAN_ROWS_BUFFER:
                state["rows"] = state["rows"][-QUICK_SCAN_ROWS_BUFFER:]
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
        # Quick scans run on-demand and often from low-resource dynos/containers.
        # Keep worker count conservative to avoid "can't start new thread" and
        # premature scan termination a few seconds after start.
        quick_workers = max(4, min(32, len(hosts)))
        run_checker(
            hosts,
            max_workers=quick_workers,
            progress_callback=_on_result,
            collect_results=False,
        )
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
    if live:
        s["live_progress"] = live.get("progress", 0)
        s["live_status"] = live.get("status")
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


@api.post("/scans/<sid>/pause")
def pause_scan_route(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    if not pause_scan(sid):
        return err("Scan is not running", 409)
    live = get_scan_state(sid) or {"id": sid, "status": "paused"}
    db.scan_update(sid, status="paused")
    broadcast("scan_update", {"id": sid, **live, "status": "paused"})
    return ok({"scan_id": sid, "status": "paused"})


@api.post("/scans/<sid>/resume")
def resume_scan_route(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    if not resume_scan(sid):
        return err("Scan is not paused", 409)
    live = get_scan_state(sid) or {"id": sid, "status": "running"}
    db.scan_update(sid, status="running")
    broadcast("scan_update", {"id": sid, **live, "status": "running"})
    return ok({"scan_id": sid, "status": "running"})


@api.post("/scans/<sid>/stop")
def stop_scan_route(sid):
    if not db.scan_get(sid):
        return err("Scan not found", 404)
    if not stop_scan(sid):
        return err("Scan is not active", 409)
    live = get_scan_state(sid) or {"id": sid, "status": "stopping"}
    db.scan_update(sid, status="stopping")
    broadcast("scan_update", {"id": sid, **live, "status": "stopping"})
    return ok({"scan_id": sid, "status": "stopping"})


@api.post("/quick-scan")
def start_quick_scan():
    d = request.json or {}
    hosts_raw = d.get("hosts", "") or ""
    hosts = parse_hosts_file(hosts_raw)
    hosts = sorted({_normalize_hostname(h) for h in hosts if _normalize_hostname(h)})
    if not hosts:
        return err("Paste at least one valid hostname")
    if len(hosts) > 50000:
        return err("Quick scan supports up to 50000 hosts at once")
    sid = _start_quick_scan(hosts)
    return ok({"scan_id": sid, "total": len(hosts), "status": "running"})


@api.get("/quick-scan/<sid>")
def quick_scan_status(sid):
    with _quick_scan_lock:
        state = dict(_quick_scan_state.get(sid) or {})
    if not state:
        return err("Quick scan not found", 404)
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


@api.get("/alert-settings")
def get_alert_settings():
    return ok(db.alert_settings_get())


@api.put("/alert-settings")
def update_alert_settings():
    d = request.json or {}
    previous = db.alert_settings_get()
    cleaned = {
        "telegram_enabled": d.get("telegram_enabled"),
        "telegram_bot_token": (d.get("telegram_bot_token") or "").strip(),
        "telegram_chat_id": (d.get("telegram_chat_id") or "").strip(),
        "slack_enabled": d.get("slack_enabled"),
        "slack_webhook_url": (d.get("slack_webhook_url") or "").strip(),
        "discord_enabled": d.get("discord_enabled"),
        "discord_webhook_url": (d.get("discord_webhook_url") or "").strip(),
        "rule_mismatch": d.get("rule_mismatch"),
        "rule_expired": d.get("rule_expired"),
        "rule_expiring": d.get("rule_expiring"),
        "rule_error": d.get("rule_error"),
        "mismatch_scope_filter": (d.get("mismatch_scope_filter") or "all").strip(),
        "minimum_days_left": d.get("minimum_days_left", 30),
    }
    out = db.alert_settings_update(**cleaned)
    discord_turned_on = bool(out.get("discord_enabled")) and not bool(previous.get("discord_enabled"))
    discord_webhook_changed = (out.get("discord_webhook_url") or "") != (previous.get("discord_webhook_url") or "")
    if bool(out.get("discord_enabled")) and (discord_turned_on or discord_webhook_changed):
        # Re-queue existing unresolved alerts so a newly enabled/updated Discord webhook
        # can receive them on the next scan dispatch.
        db.alerts_mark_all_unsent()
    return ok(out)


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


def _subdomain_tool_public_state(sid: str) -> dict:
    with _subdomain_tool_lock:
        state = dict(_subdomain_tool_state.get(sid) or {})
    if not state:
        state = db.subdomain_tool_scan_get(sid) or {}
    if state:
        state.pop("process", None)
    return state


def _subdomain_tool_worker(sid: str):
    from subfinder.runner import _build_subfinder_cmd, _is_host_within_root, _normalize_host, _resolve_subfinder_bin, _HOST_RE, enumerate_passive_subdomains, _passive_source_urls

    with _subdomain_tool_lock:
        state = _subdomain_tool_state.get(sid) or {}
        domain = state.get("domain", "")
    subfinder_bin = _resolve_subfinder_bin()
    cmd = _build_subfinder_cmd(subfinder_bin, domain) if subfinder_bin else []
    found: set[str] = set()
    stderr_lines: list[str] = []
    stderr_text = ""
    try:
        proc = None
        if cmd:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        with _subdomain_tool_lock:
            if proc:
                _subdomain_tool_processes[sid] = proc
            state = _subdomain_tool_state.get(sid)
            if state:
                state.update({"status": "running", "command": " ".join(cmd) if cmd else "built-in passive sources: " + ", ".join(_passive_source_urls(domain).keys()), "pid": proc.pid if proc else None})
        db.subdomain_tool_scan_update(sid, status="running", command=" ".join(cmd) if cmd else "built-in passive sources: " + ", ".join(_passive_source_urls(domain).keys()), pid=proc.pid if proc else None)
        broadcast("subdomain_tool_update", _subdomain_tool_public_state(sid))

        def _read_stderr():
            if proc is None or proc.stderr is None:
                return
            for err_line in proc.stderr:
                stderr_lines.append(err_line)

        stderr_thread = threading.Thread(target=_read_stderr, daemon=True, name=f"subdomain-tool-stderr-{sid[:8]}")
        stderr_thread.start()

        if proc and proc.stdout is not None:
            for line in proc.stdout:
                host = _normalize_host(line.strip())
                if host and _HOST_RE.match(host) and _is_host_within_root(host, domain) and host not in found:
                    found.add(host)
                    with _subdomain_tool_lock:
                        state = _subdomain_tool_state.get(sid)
                        if not state:
                            continue
                        state["subdomains"] = sorted(found)
                        state["total_found"] = len(found)
                        state["updated_at"] = db.now()
                        status = state.get("status")
                    db.subdomain_tool_scan_update(sid, subdomains=sorted(found), total_found=len(found))
                    broadcast("subdomain_tool_result", {"scan_id": sid, "subdomain": host, "total_found": len(found), "status": status})
            proc.wait(timeout=2)
            stderr_thread.join(timeout=1)
        passive = enumerate_passive_subdomains(domain)
        for host in passive.get("found") or []:
            if host not in found:
                found.add(host)
                db.subdomain_tool_scan_update(sid, subdomains=sorted(found), total_found=len(found))
                broadcast("subdomain_tool_result", {"scan_id": sid, "subdomain": host, "total_found": len(found), "status": "running"})
        if passive.get("errors"):
            log.warning("Subdomain passive source warnings for %s: %s", domain, passive.get("errors"))
        stderr_text = "".join(stderr_lines)
        code = proc.returncode if proc else 0
        with _subdomain_tool_lock:
            state = _subdomain_tool_state.get(sid)
            current_status = state.get("status") if state else ""
            final_status = "stopped" if current_status == "stopping" or code in {-15, -9} else ("done" if code == 0 else "error")
            if state:
                finished_at = db.now()
                state.update({"status": final_status, "exit_code": code, "stderr": stderr_text or "", "finished_at": finished_at, "total_found": len(found), "subdomains": sorted(found)})
                db.subdomain_tool_scan_update(sid, status=final_status, exit_code=code, stderr=stderr_text or "", finished_at=finished_at, total_found=len(found), subdomains=sorted(found))
    except Exception as e:
        with _subdomain_tool_lock:
            state = _subdomain_tool_state.get(sid)
            if state:
                stderr_text = stderr_text or "".join(stderr_lines)
                finished_at = db.now()
                state.update({"status": "error", "error": str(e), "stderr": stderr_text or str(e), "finished_at": finished_at, "subdomains": sorted(found), "total_found": len(found)})
                db.subdomain_tool_scan_update(sid, status="error", error=str(e), stderr=stderr_text or str(e), finished_at=finished_at, subdomains=sorted(found), total_found=len(found))
    finally:
        with _subdomain_tool_lock:
            _subdomain_tool_processes.pop(sid, None)
        broadcast("subdomain_tool_update", _subdomain_tool_public_state(sid))


@api.post("/tools/subdomains")
def enumerate_subdomains_tool():
    d = request.json or {}
    domain = _normalize_domain(d.get("domain", ""))
    if not domain:
        return err("Enter a valid domain, for example example.com")
    sid = db.uid()
    db.subdomain_tool_scan_create(sid, domain)
    with _subdomain_tool_lock:
        _subdomain_tool_state[sid] = db.subdomain_tool_scan_get(sid)
    th = threading.Thread(target=_subdomain_tool_worker, args=(sid,), daemon=True, name=f"subdomain-tool-{sid[:8]}")
    with _subdomain_tool_lock:
        _subdomain_tool_threads[sid] = th
    th.start()
    from subfinder.runner import subfinder_available
    return ok({"scan_id": sid, "domain": domain, "status": "queued", "binary_available": subfinder_available()})


@api.get("/tools/subdomains/latest")
def subdomain_tool_latest():
    state = db.subdomain_tool_scan_latest()
    if not state:
        return ok(None)
    return ok(state)


@api.get("/tools/subdomains")
def subdomain_tool_history():
    try:
        limit = int(request.args.get("limit", 20))
    except ValueError:
        limit = 20
    return ok(db.subdomain_tool_scans_list(limit=limit))


@api.get("/tools/subdomains/<sid>")
def subdomain_tool_status(sid):
    state = _subdomain_tool_public_state(sid)
    if not state:
        return err("Subdomain enumeration scan not found", 404)
    return ok(state)


@api.post("/tools/subdomains/<sid>/pause")
def pause_subdomain_tool(sid):
    with _subdomain_tool_lock:
        proc = _subdomain_tool_processes.get(sid)
        state = _subdomain_tool_state.get(sid)
        if not proc or not state or state.get("status") != "running":
            return err("Subdomain enumeration scan is not running", 409)
        os.kill(proc.pid, signal.SIGSTOP)
        state["status"] = "paused"
        state["updated_at"] = db.now()
        db.subdomain_tool_scan_update(sid, status="paused")
    payload = _subdomain_tool_public_state(sid)
    broadcast("subdomain_tool_update", payload)
    return ok(payload)


@api.post("/tools/subdomains/<sid>/resume")
def resume_subdomain_tool(sid):
    with _subdomain_tool_lock:
        proc = _subdomain_tool_processes.get(sid)
        state = _subdomain_tool_state.get(sid)
        if not proc or not state or state.get("status") != "paused":
            return err("Subdomain enumeration scan is not paused", 409)
        os.kill(proc.pid, signal.SIGCONT)
        state["status"] = "running"
        state["updated_at"] = db.now()
        db.subdomain_tool_scan_update(sid, status="running")
    payload = _subdomain_tool_public_state(sid)
    broadcast("subdomain_tool_update", payload)
    return ok(payload)


@api.post("/tools/subdomains/<sid>/stop")
def stop_subdomain_tool(sid):
    with _subdomain_tool_lock:
        proc = _subdomain_tool_processes.get(sid)
        state = _subdomain_tool_state.get(sid)
        if not state or state.get("status") not in ACTIVE_SUBDOMAIN_TOOL_STATUSES:
            return err("Subdomain enumeration scan is not active", 409)
        was_paused = state.get("status") == "paused"
        state["status"] = "stopping"
        state["updated_at"] = db.now()
        db.subdomain_tool_scan_update(sid, status="stopping")
        if proc:
            if was_paused:
                os.kill(proc.pid, signal.SIGCONT)
            proc.terminate()
    payload = _subdomain_tool_public_state(sid)
    broadcast("subdomain_tool_update", payload)
    return ok(payload)


@api.get("/tools/subdomains/<sid>/export.<fmt>")
def export_subdomain_tool(sid, fmt):
    state = _subdomain_tool_public_state(sid)
    if not state:
        return err("Subdomain enumeration scan not found", 404)
    rows = state.get("subdomains") or []
    domain = state.get("domain") or "subdomains"
    if fmt == "txt":
        body = "\n".join(rows) + ("\n" if rows else "")
        mimetype = "text/plain; charset=utf-8"
    elif fmt == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["subdomain"])
        for host in rows:
            writer.writerow([host])
        body = out.getvalue()
        mimetype = "text/csv; charset=utf-8"
    else:
        return err("Export format must be txt or csv", 400)
    safe_domain = "".join(ch if ch.isalnum() or ch in ".-" else "_" for ch in domain)
    return Response(body, mimetype=mimetype, headers={"Content-Disposition": f"attachment; filename=subdomains-{safe_domain}.{fmt}"})


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
