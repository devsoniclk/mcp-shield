"""Tests for the audit module."""

import json
import tempfile
import pathlib

from mcp_shield.audit import AuditLog


def test_log_creates_file():
    with tempfile.TemporaryDirectory() as td:
        audit = AuditLog(td)
        audit.log({"test": "entry"})
        files = list(pathlib.Path(td).glob("audit-*.jsonl"))
        assert len(files) == 1


def test_log_tool_call():
    with tempfile.TemporaryDirectory() as td:
        audit = AuditLog(td)
        audit.log_tool_call(
            server="test-server",
            tool_name="test_tool",
            arguments={"key": "val"},
            response_text="ok",
            detections=[],
            action="allow",
        )
        files = list(pathlib.Path(td).glob("audit-*.jsonl"))
        with open(files[0]) as f:
            entry = json.loads(f.readline())
        assert entry["type"] == "tool_call"
        assert entry["tool"] == "test_tool"
        assert entry["action"] == "allow"


def test_report_counts_flagged():
    with tempfile.TemporaryDirectory() as td:
        audit = AuditLog(td)
        audit.log_tool_call("srv", "tool1", {}, "ok", action="allow")
        audit.log_tool_call("srv", "tool2", {}, "bad", detections=[
            {"detector": "injection", "severity": "high", "message": "test"}
        ], action="block")
        report = audit.report("24h")
        assert report["total_calls"] == 2
        assert report["flagged_calls"] == 1


def test_report_empty():
    with tempfile.TemporaryDirectory() as td:
        audit = AuditLog(td)
        report = audit.report("24h")
        assert report["total_calls"] == 0
        assert report["flagged_calls"] == 0


def test_log_schema_scan():
    with tempfile.TemporaryDirectory() as td:
        audit = AuditLog(td)
        audit.log_schema_scan("evil_tool", [
            {"detector": "injection", "severity": "high", "message": "test"}
        ])
        files = list(pathlib.Path(td).glob("audit-*.jsonl"))
        with open(files[0]) as f:
            entry = json.loads(f.readline())
        assert entry["type"] == "schema_scan"
        assert entry["tool"] == "evil_tool"
