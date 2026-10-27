"""LogLens - offline log triage for security education."""
from .analyzer import analyze, create_report, parse_log

__all__ = ["analyze", "create_report", "parse_log"]
