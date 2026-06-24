import os
import subprocess
import sys
from pathlib import Path


def test_wsgi_import_initializes_database_before_first_request(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from app import app; "
            "client = app.test_client(); "
            "resp = client.get('/api/projects'); "
            "print(resp.status_code); "
            "assert resp.status_code == 200, resp.get_data(as_text=True)",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "data" / "sentinel.db").exists()
