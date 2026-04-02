"""
Alert transport and filtering for SSL Sentinel.
Supports Telegram, Slack, and Discord webhooks.
"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List

logger = logging.getLogger(__name__)


def _issue_enabled(issue_type: str, settings: Dict) -> bool:
    mapping = {
        "SSL Mismatch": bool(settings.get("rule_mismatch")),
        "Expired": bool(settings.get("rule_expired")),
        "Expiring Soon": bool(settings.get("rule_expiring")),
    }
    return mapping.get(issue_type, bool(settings.get("rule_error")))


def _scope_allowed(alert_row: Dict, settings: Dict) -> bool:
    wanted = (settings.get("mismatch_scope_filter") or "all").strip()
    if wanted == "all":
        return True
    if alert_row.get("issue_type") != "SSL Mismatch":
        return True
    return (alert_row.get("mismatch_scope") or "") == wanted


def filter_alerts(alerts: List[Dict], settings: Dict) -> List[Dict]:
    return [a for a in alerts if _issue_enabled(a.get("issue_type", ""), settings) and _scope_allowed(a, settings)]


def _plain_digest(project_name: str, alerts: List[Dict], max_rows: int = 10) -> str:
    lines = [f"🔐 SSL Sentinel Alert — {project_name}", ""]
    for a in alerts[:max_rows]:
        icon = {"SSL Mismatch": "❌", "Expired": "💀", "Expiring Soon": "⚠️"}.get(a.get("issue_type"), "🔔")
        lines.append(f"{icon} {a.get('hostname')} — {a.get('issue_type')}: {a.get('details')}")
    if len(alerts) > max_rows:
        lines.append(f"...and {len(alerts) - max_rows} more. Check dashboard.")
    return "\n".join(lines)


class TelegramNotifier:
    def __init__(self, settings: Dict):
        self.enabled = bool(settings.get("telegram_enabled"))
        self.token = settings.get("telegram_bot_token", "")
        self.chat_id = settings.get("telegram_chat_id", "")
        self.ready = bool(self.enabled and self.token and self.chat_id)

    def send_mismatch_digest(self, project_name: str, alerts: List[Dict]) -> bool:
        if not alerts:
            return True
        if not self.ready:
            return False
        lines = [f"<b>🔐 SSL Sentinel Alert — {project_name}</b>", ""]
        for a in alerts[:10]:
            icon = {"SSL Mismatch": "❌", "Expired": "💀", "Expiring Soon": "⚠️"}.get(a.get("issue_type"), "🔔")
            lines.append(f"{icon} <code>{a.get('hostname','')}</code>")
            lines.append(f"   {a.get('issue_type','Issue')}: {a.get('details','')}")
            lines.append("")
        if len(alerts) > 10:
            lines.append(f"...and {len(alerts) - 10} more. Check dashboard.")
        text = "\n".join(lines)
        try:
            payload = urllib.parse.urlencode({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "HTML",
            }).encode()
            req = urllib.request.Request(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                data=payload,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error("Telegram send failed: %s", e)
            return False


class WebhookNotifier:
    def __init__(self, name: str, enabled: bool, webhook_url: str):
        self.name = name
        self.enabled = bool(enabled)
        self.webhook_url = webhook_url or ""
        self.ready = bool(self.enabled and self.webhook_url)

    def send_mismatch_digest(self, project_name: str, alerts: List[Dict]) -> bool:
        if not alerts:
            return True
        if not self.ready:
            return False
        text = _plain_digest(project_name, alerts)
        if self.name == "discord":
            return self._send_discord_chunks(text)
        return self._send_payload({"text": text})

    def _send_payload(self, payload: Dict) -> bool:
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            logger.error("%s webhook failed: %s body=%s", self.name, e, body[:500])
            return False
        except Exception as e:
            logger.error("%s webhook send failed: %s", self.name, e)
            return False

    def _send_discord_chunks(self, text: str) -> bool:
        # Discord webhook message content limit is 2000 chars.
        # Split by lines and keep chunks below a safe threshold.
        if not text:
            return True
        chunks: List[str] = []
        current: List[str] = []
        cur_len = 0
        for line in text.splitlines():
            add = len(line) + (1 if current else 0)
            if cur_len + add > 1900:
                chunks.append("\n".join(current))
                current = [line]
                cur_len = len(line)
            else:
                current.append(line)
                cur_len += add
        if current:
            chunks.append("\n".join(current))
        return all(self._send_payload({"content": chunk}) for chunk in chunks if chunk)


class ConsoleNotifier:
    def send_mismatch_digest(self, project_name: str, alerts: List[Dict]) -> bool:
        for a in alerts:
            logger.warning("[%s] %s — %s: %s", project_name, a.get("hostname"), a.get("issue_type"), a.get("details"))
        return True


class AlertManager:
    def __init__(self, settings: Dict):
        self.settings = settings or {}
        self.notifiers = [
            TelegramNotifier(self.settings),
            WebhookNotifier("slack", self.settings.get("slack_enabled"), self.settings.get("slack_webhook_url", "")),
            WebhookNotifier("discord", self.settings.get("discord_enabled"), self.settings.get("discord_webhook_url", "")),
            ConsoleNotifier(),
        ]

    def dispatch(self, project_name: str, alerts: List[Dict]) -> None:
        scoped = filter_alerts(alerts, self.settings)
        if not scoped:
            return
        for notifier in self.notifiers:
            try:
                notifier.send_mismatch_digest(project_name, scoped)
            except Exception as e:
                logger.error("Notifier %s failed: %s", type(notifier).__name__, e)
