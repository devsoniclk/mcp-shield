"""Tests for the policy module."""

import pathlib
import tempfile

import yaml

from mcp_shield.policy import LLMJudgeConfig, Policy, load_policy

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def test_default_policy():
    policy = Policy()
    assert policy.on_violation == "block"
    assert policy.redact_secrets is True
    assert policy.detector_enabled("prompt_injection") is True
    assert policy.detector_enabled("secret_exfiltration") is True


def test_load_policy_from_yaml():
    config = {
        "defaults": {"on_violation": "warn", "redact_secrets": False},
        "servers": {
            "filesystem": {
                "tools": {
                    "write_file": {"require_approval": True},
                    "delete_file": {"block": True},
                }
            }
        },
        "detectors": {
            "prompt_injection": True,
            "secret_exfiltration": True,
            "pii": False,
            "llm_judge": {"enabled": True, "model": "claude-haiku-4-5"},
        },
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(config, f)
        path = f.name

    policy = load_policy(path)
    assert policy.on_violation == "warn"
    assert policy.redact_secrets is False
    assert policy.is_tool_blocked("filesystem", "delete_file") is True
    assert policy.is_tool_blocked("filesystem", "write_file") is False
    assert policy.requires_approval("filesystem", "write_file") is True
    assert policy.requires_approval("filesystem", "delete_file") is False

    lj = policy.detectors["llm_judge"]
    assert isinstance(lj, LLMJudgeConfig)
    assert lj.enabled is True
    assert lj.model == "claude-haiku-4-5"

    pathlib.Path(path).unlink()


def test_load_missing_policy_returns_defaults():
    policy = load_policy("/nonexistent/policy.yaml")
    assert policy.on_violation == "block"


def test_load_none_returns_defaults():
    policy = load_policy(None)
    assert policy.on_violation == "block"


def test_is_tool_blocked_unknown_server():
    policy = Policy()
    assert policy.is_tool_blocked("unknown_server", "any_tool") is False


def test_detector_enabled_for_llm_judge():
    config = {
        "detectors": {
            "llm_judge": {"enabled": True, "model": "gpt-4o"},
        }
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(config, f)
        path = f.name

    policy = load_policy(path)
    assert policy.detector_enabled("llm_judge") is True
    pathlib.Path(path).unlink()
