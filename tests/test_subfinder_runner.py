from pathlib import Path
import urllib.error
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


def test_default_passive_providers_exclude_removed_or_duplicate_public_sources():
    import subfinder.runner as runner

    names = {provider.name for provider in runner._all_enumeration_providers()}

    assert "Google Certificate Transparency" not in names
    assert "Facebook Certificate Transparency" not in names
    assert "ThreatCrowd" not in names
    assert "Cloudflare Nimbus CT Logs" not in names
    assert "Sectigo CT Logs" not in names
    assert "DigiCert CT Logs" not in names
    assert "Let's Encrypt CT Logs" not in names
    assert "crt.sh" in names
    assert "Cert Spotter" in names

def test_enumerate_passive_subdomains_deduplicates_sources(monkeypatch):
    import subfinder.runner as runner

    providers = [
        runner.EnumerationProvider("crt.sh", "Certificate Transparency", lambda domain, timeout: {"api.example.com", "*.cdn.example.com"}),
        runner.EnumerationProvider("HackerTarget", "Passive DNS", lambda domain, timeout: {"mail.example.com", "api.example.com"}),
    ]
    monkeypatch.setattr(runner, "_all_enumeration_providers", lambda: providers)

    result = runner.enumerate_passive_subdomains("example.com")

    assert result["found"] == ["api.example.com", "cdn.example.com", "mail.example.com"]
    assert result["sources"]["crt.sh"] == ["api.example.com", "cdn.example.com"]
    assert result["host_sources"]["api.example.com"] == ["HackerTarget", "crt.sh"]
    assert result["errors"] == {}


def test_public_passive_provider_failures_are_suppressed(monkeypatch):
    import subfinder.runner as runner

    def failing_provider(domain, timeout):
        raise urllib.error.HTTPError("https://source.example", 429, "Too Many Requests", None, None)

    providers = [
        runner.EnumerationProvider(
            "Public Rate Limited Source",
            "Passive DNS",
            failing_provider,
            report_errors=False,
        ),
        runner.EnumerationProvider("Working API", "Passive DNS", lambda domain, timeout: {"api.example.com"}),
    ]
    monkeypatch.setattr(runner, "_all_enumeration_providers", lambda: providers)

    result = runner.enumerate_passive_subdomains("example.com")

    assert result["found"] == ["api.example.com"]
    assert result["errors"] == {}


def test_enumerate_passive_subdomains_skips_missing_api_key_and_records_failures(monkeypatch):
    import subfinder.runner as runner

    def failing_provider(domain, timeout):
        raise TimeoutError("rate limited")

    providers = [
        runner.EnumerationProvider("Optional API", "Passive DNS", lambda domain, timeout: {"hidden.example.com"}, "MISSING_UNIT_API_KEY"),
        runner.EnumerationProvider("Failing API", "Threat Intelligence", failing_provider),
        runner.EnumerationProvider("Working API", "Threat Intelligence", lambda domain, timeout: {"OK.EXAMPLE.COM."}),
    ]
    monkeypatch.delenv("MISSING_UNIT_API_KEY", raising=False)
    monkeypatch.setattr(runner, "_all_enumeration_providers", lambda: providers)

    result = runner.enumerate_passive_subdomains("example.com")

    assert result["found"] == ["ok.example.com"]
    assert result["skipped"] == ["Optional API"]
    assert "Failing API" in result["errors"]


def test_run_subfinder_for_root_uses_subfinder_only(monkeypatch):
    import subfinder.runner as runner

    monkeypatch.setattr(runner, "_resolve_subfinder_bin", lambda: "/bin/subfinder")
    monkeypatch.setattr(runner, "_subfinder_supports_all_flag", lambda _bin: False)
    monkeypatch.setattr(runner, "enumerate_passive_subdomains", lambda _domain: (_ for _ in ()).throw(AssertionError("passive scan should not run")))

    class Result:
        stdout = "api.example.com\n"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(runner.subprocess, "run", lambda *args, **kwargs: Result())

    result = runner._run_subfinder_for_root("example.com")

    assert result["found"] == ["api.example.com"]
    assert result["sources"] == {"api.example.com": ["Subfinder"]}
    assert "built-in passive sources" not in result["command"]


def test_projects_with_root_domains_extracts_roots_from_project_host_lists(monkeypatch):
    import subfinder.runner as runner

    monkeypatch.setattr(
        "db.database.project_list",
        lambda: [
            {"id": "p1", "name": "One"},
            {"id": "p2", "name": "Empty"},
        ],
    )
    monkeypatch.setattr(
        "db.database.project_hosts",
        lambda pid: ["https://api.example.com", "www.example.org"] if pid == "p1" else [],
    )

    projects = runner.projects_with_root_domains()

    assert projects == [{"id": "p1", "name": "One", "root_domains": ["example.com", "example.org"]}]


def test_run_subfinder_for_all_projects_async_queues_all_project_roots(monkeypatch):
    import subfinder.runner as runner

    with runner._sf_lock:
        runner._sf_state.clear()

    monkeypatch.setattr(
        runner,
        "projects_with_root_domains",
        lambda: [
            {"id": "p1", "root_domains": ["example.com"]},
            {"id": "p2", "root_domains": ["example.org"]},
        ],
    )
    calls = []
    monkeypatch.setattr(runner, "run_subfinder_for_project", lambda pid, triggered_by="manual": calls.append((pid, triggered_by)))

    class FakeThread:
        def __init__(self, target, **kwargs):
            self.target = target

        def start(self):
            self.target()

    monkeypatch.setattr(runner.threading, "Thread", FakeThread)

    assert runner.run_subfinder_for_all_projects_async(triggered_by="manual") == 2
    assert calls == [("p1", "manual"), ("p2", "manual")]
