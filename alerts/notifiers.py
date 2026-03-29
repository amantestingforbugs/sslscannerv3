"""
alerts/telegram.py — Modular alert system.
Currently supports Telegram. Extend by adding new notifier classes.
"""

import logging
import os
from typing import List, Dict

logger = logging.getLogger(__name__)


class TelegramNotifier:
    """
    Sends alerts via Telegram Bot API.
    Requires: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID environment variables.
    """

    def __init__(self):
        self.token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        self.enabled = bool(self.token and self.chat_id)
        if not self.enabled:
            logger.info("Telegram alerts disabled (TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set)")

    def send(self, message: str) -> bool:
        if not self.enabled:
            return False
        try:
            import urllib.request
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            data = f"chat_id={self.chat_id}&text={urllib.parse.quote(message)}&parse_mode=HTML"
            import urllib.parse
            req = urllib.request.Request(url, data=data.encode(), method="POST")
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error("Telegram send failed: %s", e)
            return False

    def send_mismatch_digest(self, project_name: str, alerts: List[Dict]) -> bool:
        if not alerts:
            return True
        lines = [f"<b>🔐 SSL Sentinel Alert — {project_name}</b>", ""]
        for a in alerts[:10]:  # max 10 per message
            icon = {"SSL Mismatch": "❌", "Expired": "💀", "Expiring Soon": "⚠️"}.get(a["issue_type"], "🔔")
            lines.append(f"{icon} <code>{a['hostname']}</code>")
            lines.append(f"   {a['issue_type']}: {a['details']}")
            lines.append("")
        if len(alerts) > 10:
            lines.append(f"...and {len(alerts)-10} more. Check dashboard.")
        return self.send("\n".join(lines))


class ConsoleNotifier:
    """Fallback notifier — logs to console. Always enabled."""

    def send(self, message: str) -> bool:
        logger.warning("ALERT: %s", message)
        return True

    def send_mismatch_digest(self, project_name: str, alerts: List[Dict]) -> bool:
        for a in alerts:
            logger.warning("[%s] %s — %s: %s", project_name, a["hostname"], a["issue_type"], a["details"])
        return True


class AlertManager:
    """
    Dispatches alerts to all configured notifiers.
    Add new notifiers here to extend (email, Slack, PagerDuty, etc.)
    """

    def __init__(self):
        self.notifiers = [ConsoleNotifier(), TelegramNotifier()]

    def dispatch(self, project_name: str, alerts: List[Dict]) -> None:
        if not alerts:
            return
        for notifier in self.notifiers:
            try:
                notifier.send_mismatch_digest(project_name, alerts)
            except Exception as e:
                logger.error("Notifier %s failed: %s", type(notifier).__name__, e)
