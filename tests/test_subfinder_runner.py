from pathlib import Path
import urllib.error
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from subfinder.runner import _extract_project_root_domains, _normalize_host, _is_host_within_root


def test_normalize_host_handles_urls_wildcards_and_ports():
    assert _normalize_host("https://API.Example.com:8443/v1") == "api.example.com"
    assert _normalize_host("ads.xxt.com/path?from=project") == "ads.xxt.com"
    assert _normalize_host("//xx.abc.com/login") == "xx.abc.com"
    assert _normalize_host("*.shop.example.org") == "shop.example.org"
    assert _normalize_host("foo.example.net:443") == "foo.example.net"


def test_extract_project_root_domains_from_mixed_input():
    hosts = [
        "https://a.example.com/path",
        "*.b.example.com",
        "c.example.net,d.example.net",
        "api.demo.co.uk;www.demo.co.uk",
        "ads.xxt.com/path?from=project",
        "//xx.abc.com/login",
        "invalid_host",
    ]
    roots = _extract_project_root_domains(hosts)
    assert roots == ["abc.com", "demo.co.uk", "example.com", "example.net", "xxt.com"]


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



def test_manual_subfinder_run_queues_when_capacity_is_busy(monkeypatch):
    import subfinder.runner as runner

    monkeypatch.setattr(runner, "MAX_CONCURRENT_SUBFINDER_PROJECTS", 1)
    with runner._sf_lock:
        runner._sf_state.clear()
        runner._sf_pending_manual_runs.clear()
        runner._sf_state["busy-project"] = {"status": "running", "job_id": "job", "new_count": 0}

    started_threads = []

    class FakeThread:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            started_threads.append(self)

        def start(self):
            pass

    monkeypatch.setattr(runner.threading, "Thread", FakeThread)

    assert runner.run_subfinder_async("manual-project", triggered_by="manual", queue_if_busy=True) is True
    assert runner.run_subfinder_async("manual-project", triggered_by="manual", queue_if_busy=True) is True
    assert len(started_threads) == 1
    assert "manual-project" in runner._sf_pending_manual_runs

    with runner._sf_lock:
        runner._sf_state.clear()
        runner._sf_pending_manual_runs.clear()

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
    class Result:
        stdout = "api.example.com\n"
        stderr = ""
        returncode = 0

    monkeypatch.setattr(runner.subprocess, "run", lambda *args, **kwargs: Result())

    result = runner._run_subfinder_for_root("example.com")

    assert result["found"] == ["api.example.com"]
    assert result["sources"] == {"api.example.com": ["Subfinder"]}
    assert result["command"] == "/bin/subfinder -d example.com -silent -timeout 30"

def test_subfinder_raw_result_finish_preserves_live_count_and_preview(tmp_path, monkeypatch):
    from db import database as db

    db._local.c = None
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "sentinel.db")
    db.init_db()

    project_id = db.project_create("Project 1")["id"]
    job_id = db.subfinder_job_create(project_id, "example.com", by="manual")
    rid = db.subfinder_raw_result_add(job_id, project_id, "example.com", "subfinder -d example.com")
    db.subfinder_raw_result_update_live(rid, "api.example.com\ncdn.example.com", status="running")
    db.subfinder_raw_result_finish(rid, "done", 0, 0, "", "")

    rows = db.subfinder_raw_results_list(project_id)

    assert rows[0]["total_found"] == 2
    assert rows[0]["raw_lines"] == ["api.example.com", "cdn.example.com"]
