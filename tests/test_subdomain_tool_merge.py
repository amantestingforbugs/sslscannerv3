import os
import sys
import subprocess
from pathlib import Path


def test_merge_subdomain_tool_results_deduplicates_latest_completed_scans(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo)
    script = r'''
from app import app
import db.database as db

client = app.test_client()

db.subdomain_tool_scan_create("sf-old", "example.com", scan_type="subfinder")
db.subdomain_tool_scan_update("sf-old", status="done", subdomains=["old.example.com"], total_found=1, finished_at="2026-01-01T00:00:00+00:00")
db.subdomain_tool_scan_create("sf-new", "example.com", scan_type="subfinder")
db.subdomain_tool_scan_update("sf-new", status="done", subdomains=["a.example.com", "shared.example.com"], total_found=2, finished_at="2026-01-02T00:00:00+00:00")
db.subdomain_tool_scan_create("passive-new", "example.com", scan_type="passive")
db.subdomain_tool_scan_update("passive-new", status="done", subdomains=["b.example.com", "shared.example.com"], total_found=2, finished_at="2026-01-03T00:00:00+00:00")

resp = client.post("/api/tools/subdomains/merge", json={"domain": "example.com"})
assert resp.status_code == 200, resp.get_data(as_text=True)
payload = resp.get_json()["data"]
assert payload["scan_type"] == "merged"
assert payload["status"] == "done"
assert payload["subdomains"] == ["a.example.com", "b.example.com", "shared.example.com"]
assert payload["total_found"] == 3
assert payload["merged_from"] == {"subfinder": "sf-new", "passive": "passive-new"}

history = client.get("/api/tools/subdomains?limit=10").get_json()["data"]
assert [scan["id"] for scan in history if scan["domain"] == "example.com"] == [payload["id"]]
assert client.get("/api/tools/subdomains/sf-new").status_code == 404
assert client.get("/api/tools/subdomains/passive-new").status_code == 404
'''
    result = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, env=env, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr


def test_delete_subdomain_tool_scan_removes_completed_scan(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo)
    script = r'''
from app import app
import db.database as db

client = app.test_client()

db.subdomain_tool_scan_create("delete-me", "example.net", scan_type="passive")
db.subdomain_tool_scan_update("delete-me", status="done", subdomains=["a.example.net"], total_found=1, finished_at="2026-01-01T00:00:00+00:00")

resp = client.delete("/api/tools/subdomains/delete-me")
assert resp.status_code == 200, resp.get_data(as_text=True)
assert client.get("/api/tools/subdomains/delete-me").status_code == 404
assert all(scan["id"] != "delete-me" for scan in client.get("/api/tools/subdomains?limit=10").get_json()["data"])
'''
    result = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, env=env, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
