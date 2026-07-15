from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from subfinder.runner import _extract_project_root_domains, _normalize_host, _is_host_within_root


def test_normalize_host_handles_urls_wildcards_and_ports():
    assert _normalize_host("https://API.Example.com:8443/v1") == "api.example.com"
    assert _normalize_host("*.shop.example.org") == "shop.example.org"
    assert _normalize_host("foo.example.net:443") == "foo.example.net"


def test_extract_project_root_domains_from_mixed_input():
    hosts = [
        "https://a.example.com/path",
        "*.b.example.com",
        "c.example.net,d.example.net",
        "api.demo.co.uk;www.demo.co.uk",
        "invalid_host",
    ]
    roots = _extract_project_root_domains(hosts)
    assert roots == ["demo.co.uk", "example.com", "example.net"]


def test_is_host_within_root_requires_domain_boundary():
    assert _is_host_within_root("a.example.com", "example.com") is True
    assert _is_host_within_root("example.com", "example.com") is True
    assert _is_host_within_root("badexample.com", "example.com") is False


def test_subfinder_ssl_scan_streams_results_without_collecting(monkeypatch, tmp_path):
    import db.database as db
    import subfinder.runner as runner

    monkeypatch.chdir(tmp_path)
    db.init_db()
    project = db.project_create("streaming-subfinder")
    db.subfinder_hosts_add_batch(project["id"], ["a.example.com", "b.example.com"])

    calls = {}

    def fake_run_checker(hostnames, max_workers, progress_callback, collect_results=True, **kwargs):
        calls["hostnames"] = list(hostnames)
        calls["max_workers"] = max_workers
        calls["collect_results"] = collect_results
        for idx, hostname in enumerate(hostnames, start=1):
            progress_callback(
                idx,
                len(hostnames),
                {"hostname": hostname, "error": "Timeout", "is_ignored_error": True},
            )
        return [{"should_not": "be collected"}]

    monkeypatch.setattr("core.ssl_checker.run_checker", fake_run_checker)
    runner._ssl_scan_subfinder_hosts(project["id"], ["a.example.com", "b.example.com"], "job-1")

    assert calls["collect_results"] is False
    assert calls["max_workers"] <= 50
    latest = db.scan_latest(project["id"])
    assert latest["status"] == "done"
    assert latest["done"] == 2
    assert set(db.subfinder_hosts_new_unsscanned(project["id"])) == set()


def test_subfinder_scheduler_starts_only_one_due_project_per_tick(monkeypatch):
    import subfinder.runner as runner

    scheduler = runner.SubfinderScheduler()
    projects = [
        {"id": "p1", "enabled": 1, "subfinder_enabled": 1, "subfinder_interval_minutes": 10},
        {"id": "p2", "enabled": 1, "subfinder_enabled": 1, "subfinder_interval_minutes": 10},
    ]
    started = []

    monkeypatch.setattr("db.database.project_list", lambda: projects)
    monkeypatch.setattr(
        runner,
        "run_subfinder_async",
        lambda pid, triggered_by="scheduler": started.append((pid, triggered_by)) or True,
    )
    monkeypatch.setattr(runner.time, "time", lambda: 10_000)

    scheduler._tick()

    assert started == [("p1", "scheduler")]
    assert scheduler._last_run == {"p1": 10_000}
