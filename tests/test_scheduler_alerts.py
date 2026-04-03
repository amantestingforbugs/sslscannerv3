from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from scheduler.runner import _build_alert_from_result


def test_build_alert_suppresses_ignored_scan_errors():
    result = {
        "hostname": "bad.example.com",
        "error": "Timeout",
        "is_ignored_error": True,
    }
    assert _build_alert_from_result(result, expiring_threshold=30) is None


def test_build_alert_keeps_non_ignored_scan_errors():
    result = {
        "hostname": "bad.example.com",
        "error": "certificate parse failure",
        "is_ignored_error": False,
    }
    alert = _build_alert_from_result(result, expiring_threshold=30)
    assert alert == ("bad.example.com", "Scan Error", "certificate parse failure", "")

