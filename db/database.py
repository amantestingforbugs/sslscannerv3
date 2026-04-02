"""
db/database.py
Persistent SQLite layer. Per-thread connection pool, WAL mode, batch writes.
Extended with subfinder_jobs and subfinder_hosts tables.
"""

import sqlite3, json, uuid, threading, logging, zlib
from itertools import islice
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


def _compress_text(text: str):
    if not text:
        return None
    return sqlite3.Binary(zlib.compress(text.encode("utf-8"), level=6))


def _decompress_text(blob):
    if not blob:
        return ""
    try:
        return zlib.decompress(blob).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _chunked(items, size=500):
    it = iter(items)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk


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
        mismatch_scope TEXT DEFAULT '',
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
        stdout_z BLOB,
        stderr_z BLOB,
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
    CREATE TABLE IF NOT EXISTS subfinder_new_discoveries (
        id TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        discovered_at TEXT NOT NULL,
        UNIQUE(job_id, hostname),
        FOREIGN KEY(job_id) REFERENCES subfinder_jobs(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS openssl_results (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        hostname TEXT NOT NULL,
        status TEXT DEFAULT '',
        subject TEXT DEFAULT '',
        error TEXT DEFAULT '',
        exit_code INTEGER,
        source TEXT DEFAULT 'manual',
        last_checked TEXT NOT NULL,
        UNIQUE(project_id, hostname)
    );
    CREATE INDEX IF NOT EXISTS idx_res_scan  ON results(scan_id);
    CREATE INDEX IF NOT EXISTS idx_res_proj  ON results(project_id);
    CREATE INDEX IF NOT EXISTS idx_res_mis   ON results(scan_id, is_mismatch);
    CREATE INDEX IF NOT EXISTS idx_scans_proj ON scans(project_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_dd ON alerts(dedup_key);
    CREATE INDEX IF NOT EXISTS idx_alerts_seen_created ON alerts(seen, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sfhosts_proj ON subfinder_hosts(project_id);
    CREATE INDEX IF NOT EXISTS idx_sfraw_job ON subfinder_raw_results(job_id);
    CREATE INDEX IF NOT EXISTS idx_sfraw_project ON subfinder_raw_results(project_id, started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sfnew_job ON subfinder_new_discoveries(job_id);
    CREATE INDEX IF NOT EXISTS idx_sfnew_project ON subfinder_new_discoveries(project_id, discovered_at DESC);
    CREATE INDEX IF NOT EXISTS idx_results_proj_host_checked ON results(project_id, hostname, checked_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scans_triggered_by ON scans(triggered_by);
    CREATE INDEX IF NOT EXISTS idx_sfjobs_proj_started ON subfinder_jobs(project_id, started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sfnew_proj_job_host ON subfinder_new_discoveries(project_id, job_id, hostname);
    CREATE INDEX IF NOT EXISTS idx_openssl_proj_checked ON openssl_results(project_id, last_checked DESC);
    """)
    # Lightweight migrations for existing DBs
    try:
        x("ALTER TABLE subfinder_jobs ADD COLUMN raw_output_path TEXT DEFAULT ''")
        commit()
    except sqlite3.OperationalError:
        pass
    try:
        x("ALTER TABLE alerts ADD COLUMN mismatch_scope TEXT DEFAULT ''")
        commit()
    except sqlite3.OperationalError:
        pass
    try:
        x("ALTER TABLE subfinder_raw_results ADD COLUMN stdout_z BLOB")
        commit()
    except sqlite3.OperationalError:
        pass
    try:
        x("ALTER TABLE subfinder_raw_results ADD COLUMN stderr_z BLOB")
        commit()
    except sqlite3.OperationalError:
        pass
    # Data cleanup for old DBs: keep only the latest duplicate rows.
    x(
        """
        DELETE FROM alerts
        WHERE id IN (
          SELECT a.id
          FROM alerts a
          JOIN alerts newer
            ON newer.dedup_key = a.dedup_key
           AND (newer.created_at > a.created_at OR (newer.created_at = a.created_at AND newer.id > a.id))
        )
        """
    )
    x(
        """
        DELETE FROM subfinder_raw_results
        WHERE id IN (
          SELECT r.id
          FROM subfinder_raw_results r
          JOIN subfinder_raw_results newer
            ON newer.job_id = r.job_id
           AND newer.root_domain = r.root_domain
           AND (newer.started_at > r.started_at OR (newer.started_at = r.started_at AND newer.id > r.id))
        )
        """
    )
    x(
        """
        DELETE FROM subfinder_new_discoveries
        WHERE id IN (
          SELECT n.id
          FROM subfinder_new_discoveries n
          JOIN subfinder_new_discoveries newer
            ON newer.project_id = n.project_id
           AND newer.hostname = n.hostname
           AND (newer.discovered_at > n.discovered_at OR (newer.discovered_at = n.discovered_at AND newer.id > n.id))
        )
        """
    )
    try:
        x("CREATE UNIQUE INDEX IF NOT EXISTS idx_sfraw_job_root_unique ON subfinder_raw_results(job_id, root_domain)")
    except sqlite3.IntegrityError:
        pass
    try:
        x("CREATE UNIQUE INDEX IF NOT EXISTS idx_sfnew_project_host_unique ON subfinder_new_discoveries(project_id, hostname)")
    except sqlite3.IntegrityError:
        pass
    commit()
    log.info("DB ready at %s", DB_PATH)


# ── Projects ──────────────────────────────────────────────────────────────────

def project_create(name, description="", scan_interval=60, subfinder_interval=30):
    subfinder_interval = max(10, min(30, int(subfinder_interval or 30)))
    pid, n = uid(), now()
    x("INSERT INTO projects(id,name,description,scan_interval_minutes,subfinder_interval_minutes,created_at,updated_at)"
      " VALUES(?,?,?,?,?,?,?)", (pid, name, description, scan_interval, subfinder_interval, n, n))
    commit()
    return project_get(pid)

def project_get(pid):
    r = x(
        "SELECT id,name,description,host_count,scan_interval_minutes,"
        "subfinder_interval_minutes,subfinder_enabled,enabled,created_at,updated_at "
        "FROM projects WHERE id=?",
        (pid,),
    ).fetchone()
    return dict(r) if r else None

def project_get_by_name(name):
    r = x("SELECT * FROM projects WHERE name=?", (name,)).fetchone()
    return dict(r) if r else None

def project_list():
    return [
        dict(r)
        for r in x(
            "SELECT id,name,description,host_count,scan_interval_minutes,"
            "subfinder_interval_minutes,subfinder_enabled,enabled,created_at,updated_at "
            "FROM projects ORDER BY created_at DESC"
        )
    ]

def project_update(pid, **kw):
    if "subfinder_interval_minutes" in kw:
        kw["subfinder_interval_minutes"] = max(10, min(30, int(kw["subfinder_interval_minutes"] or 30)))
    kw["updated_at"] = now()
    sets = ",".join(f"{k}=?" for k in kw)
    x(f"UPDATE projects SET {sets} WHERE id=?", [*kw.values(), pid])
    commit()

def project_delete(pid):
    for t in ("results","alerts","scans","subfinder_jobs","subfinder_hosts","subfinder_new_discoveries","openssl_results"):
        x(f"DELETE FROM {t} WHERE project_id=?", (pid,))
    x("DELETE FROM projects WHERE id=?", (pid,))
    commit()

def project_hosts(pid):
    r = x("SELECT hosts_file FROM projects WHERE id=?", (pid,)).fetchone()
    if not r or not r["hosts_file"]:
        return []
    return [h.strip() for h in r["hosts_file"].splitlines() if h.strip()]

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

def alert_add(pid, hostname, issue, detail, scan_id="", mismatch_scope=""):
    host = (hostname or "").strip().lower()
    dedup = f"{pid}:{host}:{issue}"
    existing = x("SELECT id FROM alerts WHERE dedup_key=?", (dedup,)).fetchone()
    if existing:
        x("UPDATE alerts SET scan_id=?,details=?,mismatch_scope=?,created_at=?,seen=0,sent=0 WHERE id=?",
          (scan_id, detail, mismatch_scope or "", now(), existing["id"]))
        commit()
        return False
    x("INSERT INTO alerts(id,project_id,scan_id,hostname,issue_type,details,mismatch_scope,dedup_key,created_at)"
      " VALUES(?,?,?,?,?,?,?,?,?)", (uid(), pid, scan_id, host, issue, detail, mismatch_scope or "", dedup, now()))
    commit()
    return True

def alerts_get(search="", mismatch_scope="all", page=1, per_page=200):
    clauses = ["1=1"]
    params = []
    if search:
        clauses.append("LOWER(a.hostname) LIKE ?")
        params.append(f"%{search.lower()}%")
    if mismatch_scope in ("same_domain", "different_domain"):
        clauses.append("a.mismatch_scope=?")
        params.append(mismatch_scope)
    where = " AND ".join(clauses)
    dedup_sql = (
        "SELECT * FROM ("
        " SELECT a.*, ROW_NUMBER() OVER ("
        "   PARTITION BY a.project_id, a.hostname, a.issue_type"
        "   ORDER BY a.created_at DESC, a.id DESC"
        " ) AS rn"
        " FROM alerts a"
        ") WHERE rn=1"
    )
    total = x(
        f"SELECT COUNT(*) FROM ({dedup_sql}) a"
        f" JOIN projects p ON p.id=a.project_id WHERE {where}",
        params,
    ).fetchone()[0]
    offset = (page - 1) * per_page
    rows = [dict(r) for r in x(
        f"SELECT a.*,p.name project_name FROM ({dedup_sql}) a"
        f" JOIN projects p ON p.id=a.project_id WHERE {where}"
        " ORDER BY a.created_at DESC LIMIT ? OFFSET ?",
        params + [per_page, offset],
    )]
    return {
        "alerts": rows,
        "total": total,
        "page": page,
        "pages": max(1, (total + per_page - 1) // per_page),
        "per_page": per_page,
    }

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

    existing = set()
    # SQLite has a hard cap on bound SQL variables per statement.
    for chunk in _chunked(deduped, 500):
        placeholders = ",".join(["?"] * len(chunk))
        rows = x(
            f"SELECT hostname FROM subfinder_hosts WHERE project_id=? AND hostname IN ({placeholders})",
            [pid, *chunk],
        ).fetchall()
        existing.update(r["hostname"] for r in rows)

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


def subfinder_new_discoveries_add_batch(job_id, pid, hostnames):
    deduped = sorted({(h or "").strip().lower() for h in hostnames if (h or "").strip()})
    if not deduped:
        return 0
    ts = now()
    rows = [(uid(), job_id, pid, h, ts) for h in deduped]
    xm("INSERT OR IGNORE INTO subfinder_new_discoveries(id,job_id,project_id,hostname,discovered_at)"
       " VALUES(?,?,?,?,?)", rows)
    commit()
    return x(
        "SELECT COUNT(*) FROM subfinder_new_discoveries WHERE job_id=?",
        (job_id,),
    ).fetchone()[0]


def subfinder_discoveries(pid, page=1, per_page=200, search="", mode="all"):
    search_like = f"%{search.lower()}%"
    if mode == "latest":
        where = "WHERE h.project_id=? AND EXISTS (SELECT 1 FROM subfinder_new_discoveries n WHERE n.project_id=h.project_id AND n.hostname=h.hostname)"
        params = [pid]
    elif mode == "last_job":
        where = (
            "WHERE h.project_id=? AND EXISTS ("
            "SELECT 1 FROM subfinder_new_discoveries n "
            "WHERE n.project_id=h.project_id AND n.hostname=h.hostname "
            "AND n.job_id=(SELECT j.id FROM subfinder_jobs j WHERE j.project_id=? ORDER BY j.started_at DESC LIMIT 1)"
            ")"
        )
        params = [pid, pid]
    else:
        where = "WHERE h.project_id=?"
        params = [pid]
    if search:
        where += " AND LOWER(h.hostname) LIKE ?"
        params.append(search_like)
    total = x(f"SELECT COUNT(*) FROM subfinder_hosts h {where}", params).fetchone()[0]
    offset = (page - 1) * per_page
    rows = x(
        f"""
        WITH filtered_hosts AS (
          SELECT
            h.project_id,
            h.hostname,
            h.first_seen,
            h.last_seen,
            h.ssl_scanned
          FROM subfinder_hosts h
          {where}
          ORDER BY h.first_seen DESC
          LIMIT ? OFFSET ?
        ),
        latest_result AS (
          SELECT
            fh.project_id,
            fh.hostname,
            (
              SELECT rr.id
              FROM results rr
              JOIN scans ss ON ss.id = rr.scan_id
              WHERE rr.project_id = fh.project_id
                AND rr.hostname = fh.hostname
                AND ss.triggered_by LIKE 'subfinder:%'
              ORDER BY rr.checked_at DESC
              LIMIT 1
            ) AS result_id
          FROM filtered_hosts fh
        )
        SELECT
          fh.hostname,
          fh.first_seen,
          fh.last_seen,
          fh.ssl_scanned,
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
        FROM filtered_hosts fh
        LEFT JOIN latest_result lr
          ON lr.project_id = fh.project_id
         AND lr.hostname = fh.hostname
        LEFT JOIN results r ON r.id = lr.result_id
        ORDER BY fh.first_seen DESC
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
        "INSERT OR REPLACE INTO subfinder_raw_results(id,job_id,project_id,root_domain,command,status,started_at)"
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
        "UPDATE subfinder_raw_results "
        "SET status=?,exit_code=?,total_found=?,stdout_text='',stderr_text='',stdout_z=?,stderr_z=?,finished_at=? "
        "WHERE id=?",
        (
            status,
            exit_code,
            total_found,
            _compress_text(stdout_text),
            _compress_text(stderr_text),
            now(),
            rid,
        ),
    )
    commit()


def subfinder_raw_results_list(pid, limit=20, preview_chars=4000):
    rows = x(
        "SELECT * FROM subfinder_raw_results WHERE project_id=? ORDER BY started_at DESC LIMIT ?",
        (pid, limit),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        out_text = d.get("stdout_text") or _decompress_text(d.get("stdout_z"))
        err_text = d.get("stderr_text") or _decompress_text(d.get("stderr_z"))
        if preview_chars and len(out_text) > preview_chars:
            out_text = out_text[:preview_chars] + "\n…truncated for UI performance…"
        d["raw_preview"] = out_text
        d["raw_lines"] = [ln for ln in out_text.splitlines() if ln.strip()][:250]
        d["stderr_preview"] = err_text[:preview_chars] if preview_chars else err_text
        d.pop("stdout_z", None)
        d.pop("stderr_z", None)
        out.append(d)
    return out


# ── OpenSSL live results ─────────────────────────────────────────────────────

def openssl_results_upsert_batch(pid, rows, source="manual"):
    ts = now()
    payload = [
        (
            uid(),
            pid,
            (r.get("hostname") or "").strip().lower(),
            r.get("status", "") or "",
            r.get("subject", "") or "",
            r.get("error", "") or "",
            r.get("exit_code"),
            source,
            ts,
        )
        for r in rows
        if (r.get("hostname") or "").strip()
    ]
    if not payload:
        return 0
    xm(
        """
        INSERT INTO openssl_results(id, project_id, hostname, status, subject, error, exit_code, source, last_checked)
        VALUES(?,?,?,?,?,?,?,?,?)
        ON CONFLICT(project_id, hostname) DO UPDATE SET
          status=excluded.status,
          subject=excluded.subject,
          error=excluded.error,
          exit_code=excluded.exit_code,
          source=excluded.source,
          last_checked=excluded.last_checked
        """,
        payload,
    )
    commit()
    return len(payload)


def openssl_results_list(pid, search="", limit=2000):
    params = [pid]
    where = "WHERE project_id=?"
    if search:
        where += " AND hostname LIKE ?"
        params.append(f"%{search.strip().lower()}%")
    params.append(max(1, min(5000, int(limit or 2000))))
    rows = x(
        f"SELECT hostname,status,subject,error,exit_code,source,last_checked "
        f"FROM openssl_results {where} ORDER BY hostname ASC LIMIT ?",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


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
