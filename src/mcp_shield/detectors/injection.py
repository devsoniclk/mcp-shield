"""Prompt injection detector — regex + heuristic patterns."""

from __future__ import annotations

import base64
import re

from .base import BaseDetector, Detection, DetectionResult, Severity

# Patterns that appear in tool descriptions trying to hijack the agent
_SCHEMA_PATTERNS: list[tuple[re.Pattern, Severity, str]] = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), Severity.CRITICAL, "Ignore-instructions prompt injection"),
    (re.compile(r"you\s+are\s+now\s+", re.I), Severity.HIGH, "Role override attempt"),
    (re.compile(r"system:\s*", re.I), Severity.HIGH, "Fake system prompt prefix"),
    (re.compile(r"\[INST\]|\[/INST\]|<\|im_start\|>", re.I), Severity.HIGH, "Chat template injection"),
    (re.compile(r"do\s+not\s+(reveal|disclose|mention)\s+this", re.I), Severity.HIGH, "Hiding instruction from user"),
    (re.compile(r"send\s+(all\s+)?(data|contents?|files?)\s+to\s+https?://", re.I), Severity.CRITICAL, "Data exfiltration instruction in schema"),
    (re.compile(r"base64[\s:]+[A-Za-z0-9+/=]{20,}", re.I), Severity.MEDIUM, "Base64-encoded payload in schema"),
    # Hidden unicode (zero-width chars, RLO, etc.)
    (re.compile(r"[\u200b\u200c\u200d\u2060\ufeff\u202e\u2066\u2067\u2068\u2069]"), Severity.MEDIUM, "Hidden Unicode characters"),
]

# Patterns that appear in tool *responses* trying to inject into the agent
_CALL_PATTERNS: list[tuple[re.Pattern, Severity, str]] = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I), Severity.CRITICAL, "Ignore-instructions in response"),
    (re.compile(r"you\s+are\s+now\s+", re.I), Severity.HIGH, "Role override in response"),
    (re.compile(r"system:\s*", re.I), Severity.MEDIUM, "Fake system prompt in response"),
    (re.compile(r"\[INST\]|\[/INST\]|<\|im_start\|>", re.I), Severity.HIGH, "Chat template injection in response"),
    (re.compile(r"do\s+not\s+(reveal|disclose|mention)\s+this", re.I), Severity.HIGH, "Instruction to hide from user in response"),
    (re.compile(r"send\s+(all\s+)?(data|contents?|files?)\s+to\s+https?://", re.I), Severity.CRITICAL, "Exfiltration URL in response"),
]


def _has_hidden_base64(text: str) -> list[Detection]:
    """Look for base64 strings that decode to readable instructions."""
    finds: list[Detection] = []
    for m in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        try:
            decoded = base64.b64decode(m.group()).decode("utf-8", errors="ignore")
            if any(kw in decoded.lower() for kw in ("ignore", "system", "instruction", "override", "send to", "http")):
                finds.append(Detection(detector="injection", severity=Severity.HIGH, message="Base64-encoded suspicious instruction", details={"decoded_sample": decoded[:200]}))
        except Exception:
            pass
    return finds


class InjectionDetector(BaseDetector):
    name = "prompt_injection"

    def detect_schema(self, tool_name: str, tool_description: str, tool_schema: dict) -> DetectionResult:
        detections: list[Detection] = []
        for pat, sev, msg in _SCHEMA_PATTERNS:
            if pat.search(tool_description):
                detections.append(Detection(detector=self.name, severity=sev, message=msg))
        detections.extend(_has_hidden_base64(tool_description))
        return DetectionResult(detections=detections)

    def detect_call(self, tool_name: str, arguments: dict, response_text: str) -> DetectionResult:
        detections: list[Detection] = []
        for pat, sev, msg in _CALL_PATTERNS:
            if pat.search(response_text):
                detections.append(Detection(detector=self.name, severity=sev, message=msg))
        detections.extend(_has_hidden_base64(response_text))
        return DetectionResult(detections=detections)
