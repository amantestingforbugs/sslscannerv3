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


def test_candidate_hosts_from_text_extracts_in_scope_hosts_only():
    import subfinder.runner as runner

    text = "api.example.com https://dev.example.com:443 badexample.com *.cdn.example.com other.test"

    assert runner._candidate_hosts_from_text(text, "example.com") == {
        "api.example.com",
        "dev.example.com",
        "cdn.example.com",
    }


def test_enumerate_passive_subdomains_deduplicates_sources(monkeypatch):
    import subfinder.runner as runner

    responses = {
        "crt.sh": ('application/json', '[{"name_value":"api.example.com\\n*.cdn.example.com"}]'),
        "HackerTarget": ('text/plain', 'mail.example.com,1.2.3.4\n'),
    }
    monkeypatch.setattr(runner, "_passive_source_urls", lambda domain: {k: f"https://unit.test/{k}" for k in responses})
    monkeypatch.setattr(runner, "_fetch_passive_url", lambda url, timeout: responses[url.rsplit('/', 1)[-1]])

    result = runner.enumerate_passive_subdomains("example.com")

    assert result["found"] == ["api.example.com", "cdn.example.com", "mail.example.com"]
    assert result["sources"]["crt.sh"] == ["api.example.com", "cdn.example.com"]
    assert result["errors"] == {}


def test_enumerate_passive_subdomains_treats_source_errors_as_nonfatal(monkeypatch):
    import urllib.error
    import subfinder.runner as runner

    monkeypatch.setattr(
        runner,
        "_passive_source_urls",
        lambda domain: {
            "FastSource": "https://unit.test/fast",
            "RateLimitedSource": "https://unit.test/limited",
        },
    )

    def fake_fetch(url, timeout):
        if url.endswith("limited"):
            raise urllib.error.HTTPError(url, 429, "Too Many Requests", None, None)
        return "text/plain", "api.example.com\n"

    monkeypatch.setattr(runner, "_fetch_passive_url", fake_fetch)

    result = runner.enumerate_passive_subdomains("example.com")

    assert result["found"] == ["api.example.com"]
    assert result["sources"]["RateLimitedSource"] == []
    assert "RateLimitedSource" in result["errors"]
