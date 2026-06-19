"""Static tool-schema analysis — runs all enabled detectors on tool definitions."""

from __future__ import annotations

from typing import Any

from .detectors.base import BaseDetector, DetectionResult
from .detectors.injection import InjectionDetector
from .detectors.secrets import SecretDetector


def _get_all_text(tool_def: dict) -> str:
    """Extract all text from a tool definition for scanning."""
    parts: list[str] = []
    if desc := tool_def.get("description", ""):
        parts.append(desc)
    if name := tool_def.get("name", ""):
        parts.append(name)
    # Walk inputSchema properties for description fields
    schema = tool_def.get("inputSchema", {})
    for prop_name, prop_def in schema.get("properties", {}).items():
        if isinstance(prop_def, dict):
            if pd := prop_def.get("description", ""):
                parts.append(pd)
    return "\n".join(parts)


class Scanner:
    """Runs detectors against tool schemas."""

    def __init__(self, detectors: list[BaseDetector] | None = None):
        self.detectors = detectors or [InjectionDetector(), SecretDetector()]

    def scan_tool(self, tool_def: dict) -> dict[str, DetectionResult]:
        """Scan a single tool definition. Returns {detector_name: result}."""
        name = tool_def.get("name", "<unknown>")
        desc = _get_all_text(tool_def)
        schema = tool_def.get("inputSchema", {})
        results: dict[str, DetectionResult] = {}
        for det in self.detectors:
            result = det.detect_schema(name, desc, schema)
            if result.has_findings:
                results[det.name] = result
        return results

    def scan_tools(self, tool_defs: list[dict]) -> dict[str, dict[str, DetectionResult]]:
        """Scan multiple tool definitions. Returns {tool_name: {detector: result}}."""
        all_results: dict[str, dict[str, DetectionResult]] = {}
        for td in tool_defs:
            name = td.get("name", "<unknown>")
            results = self.scan_tool(td)
            if results:
                all_results[name] = results
        return all_results
