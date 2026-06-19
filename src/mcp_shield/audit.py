"""Append-only JSONL audit log + report generation."""

from __future__ import annotations

import json
import os
import pathlib
import time
from datetime import datetime, timedelta, timezone
from typing import Any

DEFAULT_LOG_DIR = pathlib.Path.home() / ".mcp-shield" / "logs"


class AuditLog:
    """Append-only JSONL logger for every tool call."""

    def __init__(self, log_dir: str | pathlib.Path | None = None):
        self.log_dir = pathlib.Path(log_dir) if log_dir else DEFAULT_LOG_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _current_log(self) -> pathlib.Path:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.log_dir / f"audit-{date_str}.jsonl"

    def log(self, entry: dict[str, Any]) -> None:
        """Append a JSON entry to today's log file."""
        entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        with open(self._current_log(), "a") as f:
            f.write(json.dumps(entry) + "\n")

    def log_tool_call(
        self,
        server: str,
        tool_name: str,
        arguments: dict,
        response_text: str,
        detections: list[dict[str, Any]] | None = None,
        action: str = "allow",
    ) -> None:
        self.log({
            "type": "tool_call",
            "server": server,
            "tool": tool_name,
            "arguments": arguments,
            "response_preview": response_text[:500],
            "detections": detections or [],
            "action": action,
        })

    def log_schema_scan(self, tool_name: str, detections: list[dict[str, Any]]) -> None:
        self.log({
            "type": "schema_scan",
            "tool": tool_name,
            "detections": detections,
        })

    def _parse_since(self, since: str) -> datetime:
        """Parse '24h', '7d', '30m' etc. into a datetime cutoff."""
        now = datetime.now(timezone.utc)
        if since.endswith("h"):
            return now - timedelta(hours=int(since[:-1]))
        if since.endswith("d"):
            return now - timedelta(days=int(since[:-1]))
        if since.endswith("m"):
            return now - timedelta(minutes=int(since[:-1]))
        return now - timedelta(hours=24)

    def report(self, since: str = "24h") -> dict[str, Any]:
        """Generate a summary report of flagged calls."""
        cutoff = self._parse_since(since)
        total_calls = 0
        flagged_calls = 0
        severities: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        by_detector: dict[str, int] = {}
        flagged_entries: list[dict] = []

        for log_file in sorted(self.log_dir.glob("audit-*.jsonl")):
            with open(log_file) as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ts = entry.get("timestamp", "")
                    try:
                        entry_time = datetime.fromisoformat(ts)
                    except (ValueError, TypeError):
                        continue
                    if entry_time < cutoff:
                        continue
                    if entry.get("type") == "tool_call":
                        total_calls += 1
                        dets = entry.get("detections", [])
                        if dets:
                            flagged_calls += 1
                            flagged_entries.append(entry)
                            for d in dets:
                                sev = d.get("severity", "low")
                                severities[sev] = severities.get(sev, 0) + 1
                                det_name = d.get("detector", "unknown")
                                by_detector[det_name] = by_detector.get(det_name, 0) + 1

        return {
            "period": since,
            "total_calls": total_calls,
            "flagged_calls": flagged_calls,
            "severity_breakdown": severities,
            "by_detector": by_detector,
            "flagged_entries": flagged_entries,
        }


def print_report(report: dict[str, Any]) -> None:
    """Pretty-print a report to stdout."""
    print(f"\n{'='*60}")
    print(f"  MCP Shield — Audit Report (last {report['period']})")
    print(f"{'='*60}")
    print(f"  Total tool calls: {report['total_calls']}")
    print(f"  Flagged calls:    {report['flagged_calls']}")
    if report["total_calls"] > 0:
        pct = report["flagged_calls"] / report["total_calls"] * 100
        print(f"  Flag rate:        {pct:.1f}%")
    print()
    if any(v > 0 for v in report["severity_breakdown"].values()):
        print("  Severity breakdown:")
        for sev, count in report["severity_breakdown"].items():
            if count > 0:
                print(f"    {sev:10s} {count}")
    if report["by_detector"]:
        print("\n  By detector:")
        for det, count in report["by_detector"].items():
            print(f"    {det:25s} {count}")
    if report["flagged_entries"]:
        print(f"\n  Recent flagged calls (showing up to 10):")
        for entry in report["flagged_entries"][:10]:
            print(f"    [{entry.get('timestamp', '?')[:19]}] {entry.get('server', '?')}/{entry.get('tool', '?')} — {entry.get('action', '?')}")
    print(f"\n{'='*60}\n")
