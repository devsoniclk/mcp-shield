"""Secret / credential exfiltration detector."""

from __future__ import annotations

import re

from .base import BaseDetector, Detection, DetectionResult, Severity

# Common secret patterns — ordered by specificity
_SECRET_PATTERNS: list[tuple[re.Pattern, Severity, str]] = [
    # Cloud provider keys
    (re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL, "AWS Access Key ID"),
    (re.compile(r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*[A-Za-z0-9/+=]{40}"), Severity.CRITICAL, "AWS Secret Access Key"),
    # GitHub tokens
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), Severity.CRITICAL, "GitHub Personal Access Token"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), Severity.CRITICAL, "GitHub OAuth Token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), Severity.CRITICAL, "GitHub Fine-grained PAT"),
    # GitLab
    (re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), Severity.CRITICAL, "GitLab PAT"),
    # API keys (general pattern — short prefix, long token)
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), Severity.CRITICAL, "OpenAI / Stripe secret key"),
    # Slack tokens
    (re.compile(r"xoxb-[0-9]{10,}-[A-Za-z0-9]+"), Severity.CRITICAL, "Slack Bot Token"),
    (re.compile(r"xoxp-[0-9]{10,}-[A-Za-z0-9]+"), Severity.CRITICAL, "Slack User Token"),
    # Generic credentials
    (re.compile(r"(?i)password\s*[:=]\s*\S{8,}"), Severity.HIGH, "Password in plaintext"),
    (re.compile(r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*[A-Za-z0-9\-_]{16,}"), Severity.HIGH, "API key detected"),
    (re.compile(r"(?i)connection[_\-]?string\s*[:=]\s*\S{20,}"), Severity.HIGH, "Database connection string"),
    # Database URIs with credentials
    (re.compile(r"postgres(?:ql)?://\S+:\S+@\S+"), Severity.CRITICAL, "PostgreSQL connection URI with credentials"),
    (re.compile(r"mongodb(?:\+srv)?://\S+:\S+@\S+"), Severity.CRITICAL, "MongoDB connection URI with credentials"),
    (re.compile(r"mysql://\S+:\S+@\S+"), Severity.CRITICAL, "MySQL connection URI with credentials"),
    # Auth headers and tokens
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]{20,}=*"), Severity.HIGH, "Bearer token"),
    # Private keys
    (re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"), Severity.CRITICAL, "Private key block"),
]


class SecretDetector(BaseDetector):
    name = "secret_exfiltration"

    def _scan_text(self, text: str) -> list[Detection]:
        detections: list[Detection] = []
        for pat, sev, msg in _SECRET_PATTERNS:
            if pat.search(text):
                detections.append(Detection(detector=self.name, severity=sev, message=msg))
        return detections

    def detect_schema(self, tool_name: str, tool_description: str, tool_schema: dict) -> DetectionResult:
        return DetectionResult(detections=self._scan_text(tool_description))

    def detect_call(self, tool_name: str, arguments: dict, response_text: str) -> DetectionResult:
        detections: list[Detection] = []
        # Check response for leaked secrets
        detections.extend(self._scan_text(response_text))
        # Check arguments for secrets being sent outbound
        import json
        arg_str = json.dumps(arguments)
        detections.extend(self._scan_text(arg_str))
        return DetectionResult(detections=detections)
