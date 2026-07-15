import os
import subprocess
import sys
from pathlib import Path


def test_discovery_batch_modes_split_initial_and_latest_scheduled(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo)
    script = r'''
import db.database as db

db.init_db()
pid = db.project_create("Batch Project")["id"]
for jid, by, started in [
    ("job-initial", "manual", "2026-01-01T00:00:00+00:00"),
    ("job-scheduled-old", "scheduler", "2026-01-02T00:00:00+00:00"),
    ("job-scheduled-new", "scheduler", "2026-01-03T00:00:00+00:00"),
]:
    db.x(
        "INSERT INTO subfinder_jobs(id,project_id,domains_input,triggered_by,status,started_at,finished_at) VALUES(?,?,?,?,?,?,?)",
        (jid, pid, "example.com", by, "done", started, started),
    )
db.commit()

db.subfinder_hosts_add_batch(pid, ["first.example.com", "old.example.com", "latest.example.com"])
db.subfinder_new_discoveries_add_batch("job-initial", pid, ["first.example.com"])
db.subfinder_new_discoveries_add_batch("job-scheduled-old", pid, ["old.example.com"])
db.subfinder_new_discoveries_add_batch("job-scheduled-new", pid, ["latest.example.com"])

initial = db.subfinder_discoveries(pid, mode="initial_job")
latest = db.subfinder_discoveries(pid, mode="latest_scheduled")
assert [row["hostname"] for row in initial["rows"]] == ["first.example.com"]
assert [row["hostname"] for row in latest["rows"]] == ["latest.example.com"]
'''
    result = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, env=env, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
