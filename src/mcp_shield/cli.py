"""CLI for mcp-shield — wrap, scan, report."""

from __future__ import annotations

import json
import sys

import click

from .audit import AuditLog, print_report
from .policy import load_policy


@click.group()
@click.version_option(package_name="mcp-shield")
def cli():
    """mcp-shield — Security gateway for MCP servers."""
    pass


@cli.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.option("--policy", "-p", type=click.Path(), default=None, help="Path to YAML policy file")
@click.option("--log-dir", type=click.Path(), default=None, help="Audit log directory")
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def wrap(policy: str | None, log_dir: str | None, command: tuple):
    """Transparent MCP proxy — intercepts and inspects all tool calls.

    Example: mcp-shield wrap -- npx -y @some/mcp-server
    """
    if not command:
        click.echo("Error: provide a server command after --", err=True)
        sys.exit(1)

    from .proxy import MCPProxy

    p = load_policy(policy)
    audit = AuditLog(log_dir)
    proxy = MCPProxy(server_cmd=list(command), policy=p, audit_log=audit)
    proxy.run()


@cli.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.option("--policy", "-p", type=click.Path(), default=None, help="Path to YAML policy file")
@click.option("--log-dir", type=click.Path(), default=None, help="Audit log directory")
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def scan(policy: str | None, log_dir: str | None, command: tuple):
    """Audit mode — scan tool schemas and log everything (does not block).

    Example: mcp-shield scan -- npx -y @some/mcp-server
    """
    if not command:
        click.echo("Error: provide a server command after --", err=True)
        sys.exit(1)

    from .proxy import MCPProxy
    from .policy import Policy

    p = load_policy(policy)
    # Override to log-only mode
    p.on_violation = "log"
    audit = AuditLog(log_dir)
    proxy = MCPProxy(server_cmd=list(command), policy=p, audit_log=audit)
    proxy.run()


@cli.command()
@click.option("--since", "-s", default="24h", help="Time window (e.g., 24h, 7d, 30m)")
@click.option("--log-dir", type=click.Path(), default=None, help="Audit log directory")
@click.option("--json-output", "-j", is_flag=True, help="Output raw JSON")
def report(since: str, log_dir: str | None, json_output: bool):
    """Summarize flagged calls from the audit log.

    Example: mcp-shield report --since 7d
    """
    audit = AuditLog(log_dir)
    r = audit.report(since)
    if json_output:
        click.echo(json.dumps(r, indent=2, default=str))
    else:
        print_report(r)


@cli.command()
@click.argument("tool_file", type=click.Path(exists=True))
@click.option("--policy", "-p", type=click.Path(), default=None, help="Path to YAML policy file")
def inspect(tool_file: str, policy: str | None):
    """Scan a JSON file of tool definitions for threats.

    Example: mcp-shield inspect tools.json
    """
    from .scanner import Scanner

    with open(tool_file) as f:
        tools = json.load(f)
    if isinstance(tools, dict) and "tools" in tools:
        tools = tools["tools"]

    scanner = Scanner()
    results = scanner.scan_tools(tools)

    if not results:
        click.echo("✅ No threats detected in tool definitions.")
        return

    click.echo(f"⚠️  Threats detected in {len(results)} tool(s):\n")
    for tool_name, det_results in results.items():
        click.echo(f"  🔴 {tool_name}")
        for det_name, result in det_results.items():
            for d in result.detections:
                click.echo(f"     [{d.severity.value}] {det_name}: {d.message}")
    sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
