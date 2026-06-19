"""YAML policy loader + enforcement engine."""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass
class ToolPolicy:
    allow: bool = True
    block: bool = False
    require_approval: bool = False


@dataclass
class ServerPolicy:
    tools: dict[str, ToolPolicy] = field(default_factory=dict)


@dataclass
class LLMJudgeConfig:
    enabled: bool = False
    model: str = "gpt-4o-mini"


@dataclass
class Policy:
    on_violation: str = "block"  # block | warn | log
    redact_secrets: bool = True
    servers: dict[str, ServerPolicy] = field(default_factory=dict)
    detectors: dict[str, Any] = field(default_factory=lambda: {
        "prompt_injection": True,
        "secret_exfiltration": True,
        "pii": False,
        "llm_judge": LLMJudgeConfig(),
    })

    def is_tool_blocked(self, server_name: str, tool_name: str) -> bool:
        sp = self.servers.get(server_name)
        if sp:
            tp = sp.tools.get(tool_name)
            if tp and tp.block:
                return True
        return False

    def requires_approval(self, server_name: str, tool_name: str) -> bool:
        sp = self.servers.get(server_name)
        if sp:
            tp = sp.tools.get(tool_name)
            if tp and tp.require_approval:
                return True
        return False

    def detector_enabled(self, name: str) -> bool:
        val = self.detectors.get(name)
        if isinstance(val, bool):
            return val
        if isinstance(val, LLMJudgeConfig):
            return val.enabled
        return bool(val)


def load_policy(path: str | pathlib.Path | None) -> Policy:
    """Load a YAML policy file, falling back to defaults."""
    policy = Policy()
    if path is None:
        return policy
    path = pathlib.Path(path)
    if not path.exists():
        return policy
    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    defaults = raw.get("defaults", {})
    policy.on_violation = defaults.get("on_violation", policy.on_violation)
    policy.redact_secrets = defaults.get("redact_secrets", policy.redact_secrets)

    for srv_name, srv_def in raw.get("servers", {}).items():
        sp = ServerPolicy()
        for tool_name, tool_def in (srv_def.get("tools") or {}).items():
            sp.tools[tool_name] = ToolPolicy(
                block=tool_def.get("block", False),
                require_approval=tool_def.get("require_approval", False),
            )
        policy.servers[srv_name] = sp

    det_raw = raw.get("detectors", {})
    for key in ("prompt_injection", "secret_exfiltration", "pii"):
        if key in det_raw:
            policy.detectors[key] = bool(det_raw[key])
    if "llm_judge" in det_raw:
        lj = det_raw["llm_judge"]
        if isinstance(lj, dict):
            policy.detectors["llm_judge"] = LLMJudgeConfig(
                enabled=lj.get("enabled", False),
                model=lj.get("model", "gpt-4o-mini"),
            )

    return policy
