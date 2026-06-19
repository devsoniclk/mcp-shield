"""Transparent MCP proxy — stdio-based, intercepts tool calls and responses.

Architecture:
  stdin (from agent) → proxy reads JSON-RPC → inspects → forwards to real MCP server
  real MCP server stdout → proxy reads JSON-RPC → inspects → forwards to agent stdout
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any

from .audit import AuditLog
from .detectors.base import BaseDetector, DetectionResult
from .detectors.injection import InjectionDetector
from .detectors.secrets import SecretDetector
from .policy import Policy


def _detections_to_dicts(result: DetectionResult) -> list[dict[str, Any]]:
    return [
        {"detector": d.detector, "severity": d.severity.value, "message": d.message, "details": d.details}
        for d in result.detections
    ]


class MCPProxy:
    """Transparent stdio MCP proxy that inspects messages."""

    def __init__(
        self,
        server_cmd: list[str],
        policy: Policy,
        detectors: list[BaseDetector] | None = None,
        audit_log: AuditLog | None = None,
    ):
        self.server_cmd = server_cmd
        self.policy = policy
        self.detectors = detectors or [InjectionDetector(), SecretDetector()]
        self.audit = audit_log or AuditLog()
        self._tool_defs: dict[str, dict] = {}  # cached tool definitions

    def _scan_tool_definitions(self, tools: list[dict]) -> None:
        """Scan and cache tool definitions, log findings."""
        for td in tools:
            name = td.get("name", "<unknown>")
            self._tool_defs[name] = td
            for det in self.detectors:
                result = det.detect_schema(name, td.get("description", ""), td.get("inputSchema", {}))
                if result.has_findings:
                    self.audit.log_schema_scan(name, _detections_to_dicts(result))

    def _check_call(self, tool_name: str, arguments: dict, response_text: str) -> tuple[str, list[dict]]:
        """Check a tool call against detectors and policy. Returns (action, detections)."""
        all_detections: list[dict] = []

        # Policy checks
        if self.policy.is_tool_blocked("", tool_name):
            all_detections.append({"detector": "policy", "severity": "critical", "message": f"Tool {tool_name} is blocked by policy"})
            return self.policy.on_violation, all_detections

        # Run detectors on the call
        for det in self.detectors:
            result = det.detect_call(tool_name, arguments, response_text)
            if result.has_findings:
                all_detections.extend(_detections_to_dicts(result))

        if all_detections:
            return self.policy.on_violation, all_detections
        return "allow", []

    def _redact_secrets(self, text: str) -> str:
        """Redact detected secrets from text."""
        if not self.policy.redact_secrets:
            return text
        import re
        text = re.sub(r"AKIA[0-9A-Z]{16}", "[REDACTED-AWS-KEY]", text)
        text = re.sub(r"ghp_[A-Za-z0-9]{36}", "[REDACTED-GITHUB-TOKEN]", text)
        text = re.sub(r"sk-[A-Za-z0-9]{32,}", "[REDACTED-SECRET-KEY]", text)
        text = re.sub(r"(?i)password\s*[:=]\s*\S{8,}", "password=[REDACTED]", text)
        return text

    def _process_inbound(self, message: dict) -> dict:
        """Process a message from the agent (outbound to server). Inspect tool calls."""
        method = message.get("method", "")
        params = message.get("params", {})

        # Intercept tools/call to check arguments and eventually response
        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            # We store the tool name/response-id to match later
            msg_id = message.get("id")
            if msg_id is not None:
                self._pending_calls[msg_id] = {"tool": tool_name, "arguments": arguments}

        # Intercept tools/list response to scan definitions
        return message

    def _process_outbound(self, message: dict) -> dict:
        """Process a message from the server (outbound to agent). Inspect responses."""
        msg_id = message.get("id")
        if msg_id and msg_id in self._pending_calls:
            call_info = self._pending_calls.pop(msg_id)
            tool_name = call_info["tool"]
            arguments = call_info["arguments"]

            # Extract response text
            result = message.get("result", {})
            content = result.get("content", [])
            response_text = ""
            if isinstance(content, list):
                response_text = "\n".join(c.get("text", "") for c in content if isinstance(c, dict))
            elif isinstance(content, str):
                response_text = content

            # Check call
            action, detections = self._check_call(tool_name, arguments, response_text)

            # Log
            self.audit.log_tool_call(
                server="proxied",
                tool_name=tool_name,
                arguments=arguments,
                response_text=response_text,
                detections=detections,
                action=action,
            )

            if action == "block" and detections:
                # Replace response with error
                message = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32000,
                        "message": f"[mcp-shield] Tool call blocked: {detections[0].get('message', 'policy violation')}",
                    },
                }

            if action == "redact" or self.policy.redact_secrets:
                if isinstance(result, dict) and "content" in result:
                    for item in result.get("content", []):
                        if isinstance(item, dict) and "text" in item:
                            item["text"] = self._redact_secrets(item["text"])

        # Scan tool definitions if this is a tools/list response
        result = message.get("result", {})
        if isinstance(result, dict) and "tools" in result:
            self._scan_tool_definitions(result["tools"])

        return message

    def run(self) -> None:
        """Run the proxy: start the real MCP server as subprocess, forward messages."""
        self._pending_calls: dict[int, dict] = {}

        proc = subprocess.Popen(
            self.server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def forward_to_server():
            """Read from agent stdin, process, forward to server stdin."""
            try:
                for line in sys.stdin.buffer:
                    try:
                        message = json.loads(line)
                        message = self._process_inbound(message)
                        proc.stdin.write(json.dumps(message).encode() + b"\n")
                        proc.stdin.flush()
                    except json.JSONDecodeError:
                        proc.stdin.write(line)
                        proc.stdin.flush()
            except (BrokenPipeError, EOFError):
                pass
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

        def forward_to_agent():
            """Read from server stdout, process, forward to agent stdout."""
            try:
                for line in proc.stdout:
                    try:
                        message = json.loads(line)
                        message = self._process_outbound(message)
                        sys.stdout.buffer.write(json.dumps(message).encode() + b"\n")
                        sys.stdout.buffer.flush()
                    except json.JSONDecodeError:
                        sys.stdout.buffer.write(line)
                        sys.stdout.buffer.flush()
            except (BrokenPipeError, EOFError):
                pass

        to_server = threading.Thread(target=forward_to_server, daemon=True)
        to_agent = threading.Thread(target=forward_to_agent, daemon=True)
        to_server.start()
        to_agent.start()

        proc.wait()
        to_server.join(timeout=5)
        to_agent.join(timeout=5)
