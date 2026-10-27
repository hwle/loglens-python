"""Offline detection of suspicious patterns in JSONL authentication logs.

Educational triage utility. A pattern is an indicator, not proof of compromise.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import json
from pathlib import Path
from typing import Any

SUPPORTED_ACTIONS = {"login_failed", "login_success", "permission_denied"}


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    ip: str
    user: str
    action: str


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    timestamp: str
    ip: str
    user: str
    detail: str


def parse_log(path: Path) -> tuple[list[Event], list[str]]:
    """Parse JSON Lines with precise error reporting and no network access."""
    events: list[Event] = []
    errors: list[str] = []
    with path.open("r", encoding="utf-8") as source:
        for lineno, raw in enumerate(source, start=1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
                if not isinstance(obj, dict):
                    raise ValueError("event must be a JSON object")
                timestamp = datetime.fromisoformat(str(obj["timestamp"]).replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    raise ValueError("timestamp must include a timezone")
                timestamp = timestamp.astimezone(timezone.utc)
                ip = str(ip_address(obj["ip"]))
                user = obj["user"]
                action = obj["action"]
                if not isinstance(user, str) or not user.strip():
                    raise ValueError("user must be non-empty text")
                if action not in SUPPORTED_ACTIONS:
                    raise ValueError("unsupported action")
                events.append(Event(timestamp, ip, user, action))
            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
                errors.append(f"line {lineno}: {exc}")
    return sorted(events, key=lambda event: event.timestamp), errors


def analyze(events: list[Event]) -> list[Alert]:
    """Detect repeated failures and successes following failures.

    Events are ordered by time, not by line order. Rule thresholds are examples
    and should be adjusted for a real organization's baseline.
    """
    fail_by_ip: dict[str, deque[datetime]] = defaultdict(deque)
    fail_by_user_ip: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
    alerts: list[Alert] = []
    for event in sorted(events, key=lambda item: item.timestamp):
        if event.action == "login_failed":
            recent_ip = fail_by_ip[event.ip]
            recent_user = fail_by_user_ip[(event.user, event.ip)]
            while recent_ip and event.timestamp - recent_ip[0] > timedelta(minutes=5):
                recent_ip.popleft()
            while recent_user and event.timestamp - recent_user[0] > timedelta(minutes=10):
                recent_user.popleft()
            recent_ip.append(event.timestamp)
            recent_user.append(event.timestamp)
            if len(recent_ip) == 5:
                alerts.append(Alert(
                    "REPEATED_LOGIN_FAILURES", "medium", event.timestamp.isoformat(),
                    event.ip, "multiple", "Five login failures from one IP in five minutes",
                ))
        elif event.action == "login_success":
            recent_user = fail_by_user_ip[(event.user, event.ip)]
            while recent_user and event.timestamp - recent_user[0] > timedelta(minutes=10):
                recent_user.popleft()
            if len(recent_user) >= 3:
                alerts.append(Alert(
                    "SUCCESS_AFTER_FAILURES", "high", event.timestamp.isoformat(),
                    event.ip, event.user,
                    "Successful login following three or more recent failures",
                ))
            # A completed login closes this simple sequence for this user+IP.
            recent_user.clear()
    return alerts


def create_report(path: Path) -> dict[str, Any]:
    events, errors = parse_log(path)
    alerts = analyze(events)
    return {
        "source": path.name,
        "events_processed": len(events),
        "invalid_lines": len(errors),
        "alerts": [asdict(alert) for alert in alerts],
        "errors": errors,
        "note": "Indicators for review only; alerts do not prove an intrusion.",
    }
