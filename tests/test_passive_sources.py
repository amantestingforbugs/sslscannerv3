from pathlib import Path
import sys
import urllib.error

sys.path.append(str(Path(__file__).resolve().parents[1]))

from subfinder import passive_sources


def test_candidate_hosts_from_text_extracts_in_scope_hosts_only():
    text = "api.example.com https://dev.example.com:443 badexample.com *.cdn.example.com other.test"

    assert passive_sources.candidate_hosts_from_text(text, "example.com") == {
        "api.example.com",
        "dev.example.com",
        "cdn.example.com",
    }


def test_enumerate_passive_subdomains_deduplicates_sources(monkeypatch):
    responses = {
        "crt.sh": ('application/json', '[{"name_value":"api.example.com\\n*.cdn.example.com"}]'),
        "HackerTarget": ('text/plain', 'mail.example.com,1.2.3.4\n'),
    }
    monkeypatch.setattr(
        passive_sources,
        "passive_source_urls",
        lambda domain: {k: f"https://unit.test/{k}" for k in responses},
    )
    monkeypatch.setattr(
        passive_sources,
        "fetch_passive_url",
        lambda url, timeout: responses[url.rsplit('/', 1)[-1]],
    )

    result = passive_sources.enumerate_passive_subdomains("example.com")

    assert result["found"] == ["api.example.com", "cdn.example.com", "mail.example.com"]
    assert result["sources"]["crt.sh"] == ["api.example.com", "cdn.example.com"]
    assert result["errors"] == {}


def test_enumerate_passive_subdomains_treats_source_errors_as_nonfatal(monkeypatch):
    monkeypatch.setattr(
        passive_sources,
        "passive_source_urls",
        lambda domain: {
            "FastSource": "https://unit.test/fast",
            "RateLimitedSource": "https://unit.test/limited",
        },
    )

    def fake_fetch(url, timeout):
        if url.endswith("limited"):
            raise urllib.error.HTTPError(url, 429, "Too Many Requests", None, None)
        return "text/plain", "api.example.com\n"

    monkeypatch.setattr(passive_sources, "fetch_passive_url", fake_fetch)

    result = passive_sources.enumerate_passive_subdomains("example.com")

    assert result["found"] == ["api.example.com"]
    assert result["sources"]["RateLimitedSource"] == []
    assert "RateLimitedSource" in result["errors"]
