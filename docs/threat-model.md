# Threat Model — mcp-shield

## Overview

mcp-shield is a security proxy that sits between an AI agent and MCP (Model Context Protocol) servers. Its goal is to detect and prevent malicious behavior before it reaches the agent.

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                     Agent Environment                        │
│                                                              │
│  ┌──────────┐         ┌────────────┐         ┌──────────┐  │
│  │ AI Agent  │ ←stdio→ │ mcp-shield │ ←stdio→ │ MCP      │  │
│  │ (trusted) │         │ (guardian) │         │ Server   │  │
│  └──────────┘         └────────────┘         │ (untrusted│  │
│                                              └──────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Trusted:** The AI agent, mcp-shield itself, policy files.
**Untrusted:** MCP servers, tool definitions, tool responses.

## Attack Surface

### 1. Tool Poisoning (Schema-Level)

**Threat:** An MCP server provides tool definitions with hidden malicious instructions embedded in descriptions, parameter descriptions, or enum values.

**Attack vectors:**
- `ignore previous instructions` in tool description
- Role override attempts (`You are now...`)
- Chat template injection (`[INST]`, `<|im_start|>`)
- Base64-encoded malicious payloads
- Hidden Unicode characters (zero-width spaces, RLO)
- Exfiltration URLs embedded in descriptions

**Mitigation:** `InjectionDetector` scans all tool schema text with regex patterns and heuristic analysis.

### 2. Injection-in-Response (Runtime)

**Threat:** A tool's response contains text that attempts to override the agent's system prompt or behavior.

**Attack vectors:**
- Response contains `ignore previous instructions`
- Response includes chat template tags
- Response embeds instructions to hide actions from the user
- Response contains URLs for data exfiltration

**Mitigation:** `InjectionDetector` also scans response text after each tool call.

### 3. Silent Data Exfiltration

**Threat:** A tool response leaks secrets, credentials, or sensitive data, or arguments send secrets to a malicious server.

**Attack vectors:**
- Tool arguments contain API keys, tokens, passwords
- Response includes database connection strings with credentials
- Private keys embedded in responses
- Bearer tokens leaked through tool responses

**Mitigation:** `SecretDetector` scans both arguments and responses for known credential patterns.

### 4. Policy Bypass

**Threat:** Server attempts to bypass mcp-shield's policy enforcement.

**Attack vectors:**
- Tool name obfuscation (e.g., `write_file` vs `write-file`)
- Dynamic tool registration after initial scan
- Nested tool calls

**Mitigation:** All tool calls go through the proxy regardless of when they were registered. Policy matching uses exact names.

## Known Limitations

1. **Stdio only:** Currently only supports MCP over stdio transport. HTTP/SSE transport not yet implemented.
2. **No content redaction of tool schemas:** Blocked tools still have their definitions visible to the agent.
3. **Regex-based detection:** Pattern matching can have false positives (e.g., a legitimate "ignore previous search results" instruction) and false negatives (novel attack patterns).
4. **No rate limiting:** Not yet implemented.
5. **Approval flow:** Human-in-the-loop approval is defined in policy but the interactive flow is not yet wired up.

## Defense in Depth

mcp-shield is one layer. For comprehensive security:

1. **Use mcp-shield** to scan and filter tool definitions and calls
2. **Pin server versions** — don't use `@latest`
3. **Least privilege** — give servers only the minimum permissions they need
4. **Audit regularly** — use `mcp-shield report` to review flagged activity
5. **Enable LLM judge** for ambiguous cases (requires OpenAI API key)
6. **Combine detectors** — enable all relevant detectors for your use case
