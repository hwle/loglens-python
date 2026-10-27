# LogLens | Python Authentication Log Analyzer

A small, fully offline cybersecurity project that parses JSON Lines authentication
logs and flags patterns worth reviewing. Built with Python's standard library.

## Why this project?

Security analysts need to turn raw events into explainable observations. LogLens
is a practical demonstration of parsing, validation, time-window detection,
structured reports, and unit testing.

## Features

- Input validation: timestamps, IP addresses, event types, and JSON format.
- Detects **five login failures from one IP within five minutes**.
- Detects **a login success following three recent failures** for the same user and IP.
- Ignores malformed lines without silently losing track of them.
- Creates a JSON report and preserves rule names and evidence summaries.
- Uses documentation-reserved example IPs, not real accounts or credentials.

## Quick start

Requires Python 3.10+:

```sh
python -m pip install -e .
loglens examples/auth_events.jsonl
loglens examples/auth_events.jsonl --output report.json
python -m unittest discover -s tests -v
```

Sample output includes `REPEATED_LOGIN_FAILURES` and `SUCCESS_AFTER_FAILURES`.
All example timestamps are in UTC.

## Event schema

Each line contains a JSON object like:

```json
{"timestamp":"2026-01-13T08:01:00Z","ip":"192.0.2.44","user":"alex","action":"login_failed"}
```

Actions: `login_failed`, `login_success`, `permission_denied`. 

## Limitations / next steps

This uses simple rules, not machine learning; it may raise false positives and
should not be treated as a production intrusion detection system. In a larger
version I'd add streaming input, baselines per account, rule configuration,
privacy-aware redaction, dashboards, and broader tests.

## Ethical use

Analyze only logs you're permitted to access. Never commit real sensitive log
exports or credentials to a public repository.
