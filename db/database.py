"""
db/database.py
Persistent SQLite layer. Per-thread connection pool, WAL mode, batch writes.
Extended with subfinder_jobs and subfinder_hosts tables.
"""

import sqlite3, json, uuid, threading, logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)
DB_PATH = Path("data/sentinel.db")
_local = threading.local()


def _conn():
    if not getattr(_local, "c", None):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA cache_size=-32000")
        c.execute("PRAGMA temp_store=MEMORY")
        c.execute("PRAGMA mmap_size=268435456")
        c.execute("PRAGMA foreign_keys=ON")
        _local.c = c
    return _local.c


def x(sql, p=()):  return _conn().execute(sql, p)
def xm(sql, rows): return _conn().executemany(sql, rows)
def commit():       _conn().commit()
def now():          return datetime.now(timezone.utc).isoformat()
def uid():          return str(uuid.uuid4())


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _conn().executescript("""
    CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
        description TEXT DEFAULT '', hosts_file TEXT DEFAULT '',
        host_count INTEGER DEFAULT 0, scan_interval_minutes INTEGER DEFAULT 60,
        subfinder_interval_minutes INTEGER DEFAULT 30,
        subfinder_enabled INTEGER DEFAULT 0,
        enabled INTEGER DEFAULT 1,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
        status TEXT DEFAULT 'running', triggered_by TEXT DEFAULT 'manual',
        total INTEGER DEFAULT 0, done INTEGER DEFAULT 0,
        mismatches INTEGER DEFAULT 0, expired INTEGER DEFAULT 0,
        expiring INTEGER DEFAULT 0, errors INTEGER DEFAULT 0, ok INTEGER DEFAULT 0,
        started_at TEXT, finished_at TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS results (
        id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, project_id TEXT NOT NULL,
        hostname TEXT NOT NULL, cn TEXT DEFAULT '', sans TEXT DEFAULT '[]',
        issuer TEXT DEFAULT '', expiry TEXT DEFAULT '', days_left INTEGER,
        match_found INTEGER DEFAULT 0, same_base INTEGER DEFAULT 0,
        is_mismatch INTEGER DEFAULT 0, is_expired INTEGER DEFAULT 0,
        is_expiring INTEGER DEFAULT 0, is_ok INTEGER DEFAULT 0,
        error TEXT DEFAULT '', checked_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL, scan_id TEXT DEFAULT '',
        hostname TEXT NOT NULL, issue_type TEXT NOT NULL, details TEXT DEFAULT '',
        dedup_key TEXT NOT NULL UNIQUE, sent INTEGER DEFAULT 0,
        seen INTEGER DEFAULT 0, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS subfinder_jobs (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
        status TEXT DEFAULT 'running',
        domains_input TEXT DEFAULT '',
        raw_output_path TEXT DEFAULT '',
        new_count INTEGER DEFAULT 0,
        total_found INTEGER DEFAULT 0,
        triggered_by TEXT DEFAULT 'scheduler',
        started_at TEXT NOT NULL, finished_at TEXT
    );
    CREATE TABLE IF NOT EXISTS subfinder_raw_results (
        id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        root_domain TEXT NOT NULL,
        command TEXT DEFAULT '',
        status TEXT DEFAULT 'running',
        exit_code INTEGER,
        total_found INTEGER DEFAULT 0,
        stdout_text TEXT DEFAULT '',
        stderr_text TEXT DEFAULT '',
        started_at TEXT NOT NULL,
        finished_at TEXT,
        FOREIGN KEY(job_id) REFERENCES subfinder_jobs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS subfinder_hosts (
        id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
        hostname TEXT NOT NULL, source TEXT DEFAULT 'subfinder',
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
        ssl_scanned INTEGER DEFAULT 0,
        UNIQUE(project_id, hostname)
    );
    CREATE INDEX IF NOT EXISTS idx_res_scan  ON results(scan_id);
    CREATE INDEX IF NOT EXISTS idx_res_proj  ON results(project_id);
    CREATE INDEX IF NOT EXISTS idx_res_mis   ON results(scan_id, is_mismatch);
    CREATE INDEX IF NOT EXISTS idx_scans_proj ON scans(project_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_dd ON alerts(dedup_key);
    CREATE INDEX IF NOT EXISTS idx_sfhosts_proj ON subfinder_hosts(project_id);
    CREATE INDEX IF NOT EXISTS idx_sfraw_job ON subfinder_raw_results(job_id);
    CREATE INDEX IF NOT EXISTS idx_sfraw_project ON subfinder_raw_results(project_id, started_at DESC);
    """)
    # Lightweight migrations for existing DBs
    try:
        x("ALTER TABLE subfinder_jobs ADD COLUMN raw_output_path TEXT DEFAULT ''")
        commit()
    except sqlite3.OperationalError:
        pass
    log.info("DB ready at %s", DB_PATH)


# ── Projects ──────────────────────────────────────────────────────────────────

def project_create(name, description="", scan_interval=60, subfinder_interval=30):
    pid, n = uid(), now()
    x("INSERT INTO projects(id,name,description,scan_interval_minutes,subfinder_interval_minutes,created_at,updated_at)"
      " VALUES(?,?,?,?,?,?,?)", (pid, name, description, scan_interval, subfinder_interval, n, n))
    commit()
    return project_get(pid)

def project_get(pid):
    r = x("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    return dict(r) if r else None

def project_get_by_name(name):
    r = x("SELECT * FROM projects WHERE name=?", (name,)).fetchone()
    return dict(r) if r else None

def project_list():
    return [dict(r) for r in x("SELECT * FROM projects ORDER BY created_at DESC")]

def project_update(pid, **kw):
    kw["updated_at"] = now()
    sets = ",".join(f"{k}=?" for k in kw)
    x(f"UPDATE projects SET {sets} WHERE id=?", [*kw.values(), pid])
    commit()

def project_delete(pid):
    for t in ("results","alerts","scans","subfinder_jobs","subfinder_hosts"):
        x(f"DELETE FROM {t} WHERE project_id=?", (pid,))
    x("DELETE FROM projects WHERE id=?", (pid,))
    commit()

def project_hosts(pid):
    p = project_get(pid)
    if not p or not p["hosts_file"]:
        return []
    return [h.strip() for h in p["hosts_file"].splitlines() if h.strip()]

def project_save_hosts(pid, hosts):
    project_update(pid, hosts_file="\n".join(hosts), host_count=len(hosts))


# ── Scans ─────────────────────────────────────────────────────────────────────

def scan_create(pid, total, by="manual"):
    sid, n = uid(), now()
    x("INSERT INTO scans(id,project_id,total,triggered_by,started_at,created_at) VALUES(?,?,?,?,?,?)",
      (sid, pid, total, by, n, n))
    commit()
    return scan_get(sid)

def scan_get(sid):
    r = x("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return dict(r) if r else None

def scan_update(sid, **kw):
    sets = ",".join(f"{k}=?" for k in kw)
    x(f"UPDATE scans SET {sets} WHERE id=?", [*kw.values(), sid])
    commit()

def scan_progress(sid, done):
    x("UPDATE scans SET done=? WHERE id=?", (done, sid))
    commit()

def scan_finish(sid):
    r = x("SELECT COUNT(*) t, SUM(is_mismatch) mis, SUM(is_expired) exp,"
          " SUM(is_expiring) expi, SUM(is_ok) ok,"
          " SUM(CASE WHEN error!='' THEN 1 ELSE 0 END) err"
          " FROM results WHERE scan_id=?", (sid,)).fetchone()
    x("UPDATE scans SET status='done',finished_at=?,done=?,mismatches=?,expired=?,"
      "expiring=?,ok=?,errors=? WHERE id=?",
      (now(), r["t"], r["mis"] or 0, r["exp"] or 0,
       r["expi"] or 0, r["ok"] or 0, r["err"] or 0, sid))
    commit()

def scan_list(pid, limit=20):
    return [dict(r) for r in x(
        "SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC LIMIT ?", (pid, limit))]

def scan_latest(pid):
    r = x("SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC LIMIT 1", (pid,)).fetchone()
    return dict(r) if r else None


# ── Results (batch) ───────────────────────────────────────────────────────────

def results_batch_save(sid, pid, batch):
    n = now()
    rows = [(uid(), sid, pid,
             r.get("hostname",""), r.get("cn",""), json.dumps(r.get("sans",[])),
             r.get("issuer",""), r.get("expiry",""), r.get("days_left"),
             1 if r.get("match_found") else 0, 1 if r.get("same_base") else 0,
             1 if r.get("is_mismatch") else 0, 1 if r.get("is_expired") else 0,
             1 if r.get("is_expiring_soon") else 0, 1 if r.get("is_ok") else 0,
             r.get("error","") or "", n) for r in batch]
    xm("INSERT INTO results(id,scan_id,project_id,hostname,cn,sans,issuer,expiry,"
       "days_left,match_found,same_base,is_mismatch,is_expired,is_expiring,is_ok,error,checked_at)"
       " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    commit()

def results_get(sid, flt="all", page=1, per_page=500):
    base, p = "FROM results WHERE scan_id=?", [sid]
    if flt == "mismatch":  base += " AND is_mismatch=1"
    elif flt == "expired":  base += " AND is_expired=1"
    elif flt == "expiring": base += " AND is_expiring=1"
    elif flt == "ok":       base += " AND is_ok=1"
    elif flt == "errors":   base += " AND error!='' AND error IS NOT NULL"
    total = x(f"SELECT COUNT(*) {base}", p).fetchone()[0]
    offset = (page - 1) * per_page
    rows = x(f"SELECT * {base} ORDER BY is_mismatch DESC,is_expired DESC,hostname"
             f" LIMIT ? OFFSET ?", p + [per_page, offset]).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        try: d["sans"] = json.loads(d.get("sans") or "[]")
        except: d["sans"] = []
        out.append(d)
    return {"results": out, "total": total, "page": page,
            "pages": max(1,(total+per_page-1)//per_page), "per_page": per_page}


# ── Alerts ────────────────────────────────────────────────────────────────────

def alert_add(pid, hostname, issue, detail, scan_id=""):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    dedup = f"{pid}:{hostname}:{issue}:{today}"
    if x("SELECT id FROM alerts WHERE dedup_key=?", (dedup,)).fetchone():
        return False
    x("INSERT INTO alerts(id,project_id,scan_id,hostname,issue_type,details,dedup_key,created_at)"
      " VALUES(?,?,?,?,?,?,?,?)", (uid(), pid, scan_id, hostname, issue, detail, dedup, now()))
    commit()
    return True

def alerts_get(limit=200):
    return [dict(r) for r in x(
        "SELECT a.*,p.name project_name FROM alerts a"
        " JOIN projects p ON p.id=a.project_id ORDER BY a.created_at DESC LIMIT ?", (limit,))]

def alerts_unseen_count():
    return x("SELECT COUNT(*) FROM alerts WHERE seen=0").fetchone()[0]

def alerts_mark_all_seen():
    x("UPDATE alerts SET seen=1"); commit()

def alerts_clear():
    x("DELETE FROM alerts"); commit()

def alerts_unsent():
    return [dict(r) for r in x(
        "SELECT a.*,p.name project_name FROM alerts a"
        " JOIN projects p ON p.id=a.project_id WHERE a.sent=0")]

def alert_mark_sent(aid):
    x("UPDATE alerts SET sent=1 WHERE id=?", (aid,)); commit()


def alert_mark_seen(aid):
    x("UPDATE alerts SET seen=1 WHERE id=?", (aid,))
    commit()


# ── Subfinder ─────────────────────────────────────────────────────────────────

def subfinder_job_create(pid, domains_input, by="scheduler"):
    jid = uid()
    x("INSERT INTO subfinder_jobs(id,project_id,domains_input,triggered_by,started_at)"
      " VALUES(?,?,?,?,?)", (jid, pid, domains_input, by, now()))
    commit()
    return jid

def subfinder_job_finish(jid, new_count, total_found, raw_output_path=""):
    x("UPDATE subfinder_jobs SET status='done',finished_at=?,new_count=?,total_found=?,raw_output_path=? WHERE id=?",
      (now(), new_count, total_found, raw_output_path or "", jid))
    commit()

def subfinder_job_error(jid, msg):
    x("UPDATE subfinder_jobs SET status='error',finished_at=? WHERE id=?", (now(), jid))
    commit()

def subfinder_jobs_list(pid, limit=20):
    return [dict(r) for r in x(
        "SELECT * FROM subfinder_jobs WHERE project_id=? ORDER BY started_at DESC LIMIT ?",
        (pid, limit))]

def subfinder_hosts_add_batch(pid, hostnames):
    """Insert new hostnames, ignore duplicates. Returns (count, new_hostnames)."""
    n = now()
    deduped = sorted({(h or "").strip().lower() for h in hostnames if (h or "").strip()})
    if not deduped:
        return 0, []
    existing = {
        r["hostname"] for r in x(
            f"SELECT hostname FROM subfinder_hosts WHERE project_id=? AND hostname IN ({','.join(['?']*len(deduped))})",
            [pid, *deduped]
        ).fetchall()
    }
    new_hosts = [h for h in deduped if h not in existing]
    rows = [(uid(), pid, h, "subfinder", n, n) for h in deduped]
    xm("INSERT OR IGNORE INTO subfinder_hosts(id,project_id,hostname,source,first_seen,last_seen)"
       " VALUES(?,?,?,?,?,?)", rows)
    xm("UPDATE subfinder_hosts SET last_seen=? WHERE project_id=? AND hostname=?", [(n, pid, h) for h in deduped])
    commit()
    return len(new_hosts), new_hosts

def subfinder_hosts_new_unsscanned(pid):
    """Hostnames discovered by subfinder but not yet SSL-scanned."""
    return [r["hostname"] for r in x(
        "SELECT hostname FROM subfinder_hosts WHERE project_id=? AND ssl_scanned=0", (pid,))]

def subfinder_hosts_mark_scanned(pid, hostnames):
    xm("UPDATE subfinder_hosts SET ssl_scanned=1 WHERE project_id=? AND hostname=?",
       [(pid, h) for h in hostnames])
    commit()

def subfinder_hosts_list(pid, page=1, per_page=500):
    total = x("SELECT COUNT(*) FROM subfinder_hosts WHERE project_id=?", (pid,)).fetchone()[0]
    offset = (page-1)*per_page
    rows = x("SELECT * FROM subfinder_hosts WHERE project_id=? ORDER BY first_seen DESC LIMIT ? OFFSET ?",
             (pid, per_page, offset)).fetchall()
    return {"hosts": [dict(r) for r in rows], "total": total, "page": page,
            "pages": max(1,(total+per_page-1)//per_page)}


def subfinder_discoveries(pid, page=1, per_page=200, search=""):
    search_like = f"%{search.lower()}%"
    where = "WHERE h.project_id=?"
    params = [pid]
    if search:
        where += " AND LOWER(h.hostname) LIKE ?"
        params.append(search_like)
    total = x(f"SELECT COUNT(*) FROM subfinder_hosts h {where}", params).fetchone()[0]
    offset = (page - 1) * per_page
    rows = x(
        f"""
        SELECT
          h.hostname,
          h.first_seen,
          h.last_seen,
          h.ssl_scanned,
          r.cn,
          r.issuer,
          r.expiry,
          r.days_left,
          r.is_mismatch,
          r.same_base,
          r.is_expired,
          r.is_expiring,
          r.is_ok,
          r.error,
          r.checked_at
        FROM subfinder_hosts h
        LEFT JOIN results r
          ON r.id = (
            SELECT rr.id
            FROM results rr
            JOIN scans ss ON ss.id = rr.scan_id
            WHERE rr.project_id = h.project_id
              AND rr.hostname = h.hostname
              AND ss.triggered_by LIKE 'subfinder:%'
            ORDER BY rr.checked_at DESC
            LIMIT 1
          )
        {where}
        ORDER BY h.first_seen DESC
        LIMIT ? OFFSET ?
        """,
        params + [per_page, offset],
    ).fetchall()
    return {
        "rows": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }


def subfinder_raw_result_add(job_id, project_id, root_domain, command, started_at=None):
    rid = uid()
    x(
        "INSERT INTO subfinder_raw_results(id,job_id,project_id,root_domain,command,status,started_at)"
        " VALUES(?,?,?,?,?,'running',?)",
        (rid, job_id, project_id, root_domain, command, started_at or now()),
    )
    commit()
    return rid


def subfinder_raw_result_finish(
    rid,
    status,
    exit_code,
    total_found,
    stdout_text,
    stderr_text,
):
    x(
        "UPDATE subfinder_raw_results SET status=?,exit_code=?,total_found=?,stdout_text=?,stderr_text=?,finished_at=? WHERE id=?",
        (status, exit_code, total_found, stdout_text, stderr_text, now(), rid),
    )
    commit()


def subfinder_raw_results_list(pid, limit=20):
    rows = x(
        "SELECT * FROM subfinder_raw_results WHERE project_id=? ORDER BY started_at DESC LIMIT ?",
        (pid, limit),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["raw_lines"] = [ln for ln in (d.get("stdout_text") or "").splitlines() if ln.strip()]
        out.append(d)
    return out


# ── Global stats ──────────────────────────────────────────────────────────────

def stats_global():
    projects = x("SELECT COUNT(*) FROM projects WHERE enabled=1").fetchone()[0]
    unseen = alerts_unseen_count()
    r = x("""SELECT SUM(s.total) th, SUM(s.mismatches) mis,
                    SUM(s.expired) exp, SUM(s.expiring) expi, SUM(s.ok) ok
             FROM scans s JOIN (
               SELECT project_id, MAX(finished_at) mf FROM scans
               WHERE status='done' GROUP BY project_id
             ) l ON s.project_id=l.project_id AND s.finished_at=l.mf""").fetchone()
    sf_hosts = x("SELECT COUNT(*) FROM subfinder_hosts").fetchone()[0]
    active_scans = x("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone()[0]
    return {"projects": projects, "hosts": r["th"] or 0,
            "mismatches": r["mis"] or 0, "expired": r["exp"] or 0,
            "expiring": r["expi"] or 0, "ok": r["ok"] or 0,
            "unseen_alerts": unseen, "subfinder_hosts": sf_hosts,
            "active_scans": active_scans}
