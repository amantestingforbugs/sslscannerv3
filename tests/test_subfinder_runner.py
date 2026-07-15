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


def test_run_subfinder_async_reserves_capacity_before_thread_starts(monkeypatch):
    import subfinder.runner as runner

    monkeypatch.setattr(runner, "MAX_CONCURRENT_SUBFINDER_PROJECTS", 1)
    with runner._sf_lock:
        runner._sf_state.clear()

    started_threads = []

    class FakeThread:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            started_threads.append(self)

        def start(self):
            pass

    monkeypatch.setattr(runner.threading, "Thread", FakeThread)

    assert runner.run_subfinder_async("project-one", triggered_by="scheduler") is True
    assert runner.run_subfinder_async("project-two", triggered_by="scheduler") is False
    assert len(started_threads) == 1
    assert runner.get_sf_state("project-one")["status"] == "queued"


def test_subfinder_scheduler_does_not_mark_due_project_run_when_capacity_full(monkeypatch):
    import subfinder.runner as runner

    monkeypatch.setattr(runner, "MAX_CONCURRENT_SUBFINDER_PROJECTS", 1)
    with runner._sf_lock:
        runner._sf_state.clear()
        runner._sf_state["busy-project"] = {"status": "ssl_scanning", "job_id": "job", "new_count": 1}

    scheduler = runner.SubfinderScheduler()
    monkeypatch.setattr(runner.time, "time", lambda: 1_000_000)
    monkeypatch.setattr(
        "db.database.project_list",
        lambda: [
            {
                "id": "due-project",
                "enabled": 1,
                "subfinder_enabled": 1,
                "subfinder_interval_minutes": 10,
            }
        ],
    )

    scheduler._tick()

    assert "due-project" not in scheduler._last_run


def test_run_subfinder_async_clears_reservation_when_thread_start_fails(monkeypatch):
    import subfinder.runner as runner

    monkeypatch.setattr(runner, "MAX_CONCURRENT_SUBFINDER_PROJECTS", 1)
    with runner._sf_lock:
        runner._sf_state.clear()

    class FailingThread:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def start(self):
            raise RuntimeError("thread limit reached")

    monkeypatch.setattr(runner.threading, "Thread", FailingThread)

    assert runner.run_subfinder_async("project-one", triggered_by="scheduler") is False
    assert runner.get_sf_state("project-one") == {}


def test_subfinder_worker_marks_error_when_setup_raises(monkeypatch):
    import subfinder.runner as runner

    with runner._sf_lock:
        runner._sf_state.clear()
        runner._sf_state["project-one"] = {"status": "queued", "job_id": None, "new_count": 0}

    def fail_setup(project_id, triggered_by):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(runner, "run_subfinder_for_project", fail_setup)

    runner._run_subfinder_worker("project-one", "scheduler")

    assert runner.get_sf_state("project-one")["status"] == "error"
