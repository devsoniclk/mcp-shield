"""Abstract base class for detectors."""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Detection:
    """A single finding from a detector."""

    detector: str
    severity: Severity
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    """Aggregate result of running a detector."""

    detections: list[Detection] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.detections) > 0

    @property
    def max_severity(self) -> Severity | None:
        if not self.detections:
            return None
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return max(self.detections, key=lambda d: order.index(d.severity)).severity


class BaseDetector(ABC):
    """Every detector must implement this interface."""

    name: str = "base"

    @abstractmethod
    def detect_schema(self, tool_name: str, tool_description: str, tool_schema: dict) -> DetectionResult:
        """Scan a tool *definition* (before it is ever called)."""
        ...

    @abstractmethod
    def detect_call(self, tool_name: str, arguments: dict, response_text: str) -> DetectionResult:
        """Scan a tool *call* (request + response)."""
        ...
