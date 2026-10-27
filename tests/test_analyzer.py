import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from loglens.analyzer import Event, analyze, create_report


def event(minute: int, action: str, user: str = "omar", ip: str = "192.0.2.11") -> Event:
    return Event(datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minute), ip, user, action)


class LogLensTests(unittest.TestCase):
    def test_flags_five_failures_in_five_minutes(self):
        alerts = analyze([event(i, "login_failed") for i in range(5)])
        self.assertEqual([a.rule for a in alerts], ["REPEATED_LOGIN_FAILURES"])

    def test_flags_success_after_three_failures(self):
        alerts = analyze([event(i, "login_failed") for i in range(3)] + [event(4, "login_success")])
        self.assertEqual([a.rule for a in alerts], ["SUCCESS_AFTER_FAILURES"])

    def test_no_alert_for_spaced_out_failures(self):
        alerts = analyze([event(i * 8, "login_failed") for i in range(6)])
        self.assertEqual(alerts, [])

    def test_separates_users_for_success_rule(self):
        alerts = analyze([event(i, "login_failed", "alice") for i in range(3)] + [event(4, "login_success", "bob")])
        self.assertEqual(alerts, [])

    def test_reports_invalid_lines_without_crashing(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "events.jsonl"
            path.write_text('\n'.join([
                json.dumps({"timestamp": "2026-01-01T00:00:00Z", "ip": "192.0.2.9", "user": "omar", "action": "login_failed"}),
                "{broken}",
                json.dumps({"timestamp": "2026-01-01T00:00:00Z", "ip": "bad-ip", "user": "omar", "action": "login_failed"}),
            ]), encoding="utf-8")
            report = create_report(path)
        self.assertEqual(report["events_processed"], 1)
        self.assertEqual(report["invalid_lines"], 2)


if __name__ == "__main__":
    unittest.main()
