"""MCP server (stdio) with two tools: `audit` (overview) and `check` (detail for one aspect).

Responses are returned as a single compact JSON text: no `structuredContent` (it would duplicate the output in the
agent context) and no indentation.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from code_audit_mcp import checks

mcp = FastMCP(
    "code-audit",
    instructions=(
        "Audit for Laravel/PHP, Python, TypeScript/React and Flutter/Dart (monorepos too); never writes to the "
        "project. Start with audit, then drill down with check. Before deleting code, review `likely_false_positive`: "
        "detectors cannot see implicit usages (routes, Blade, decorators, hooks). Exceptions: .code-audit.toml."
    ),
)

CheckName = Literal["dead_code", "dependencies", "security", "vulnerabilities", "complexity", "lint"]
Severity = Literal["critical", "high", "medium", "low", "info"]
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)


def _compact(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


@mcp.tool(structured_output=False, annotations=READ_ONLY)
async def audit(path: str = ".") -> str:
    """Summary of all checks (dead code, dependencies, security, CVEs, complexity, lint) per stack,
    with totals by severity and the top 5 findings of each engine. Downloads tools on first run.

    Args:
        path: project folder (defaults to the working directory).
    """
    return _compact(await checks.run_audit(path))


@mcp.tool(structured_output=False, annotations=READ_ONLY)
async def check(name: CheckName, path: str = ".", severity: Severity = "info", file: str = "", offset: int = 0,
                limit: int = checks.PAGE_SIZE, false_positives: bool = False) -> str:
    """Findings of one check, sorted by severity and paginated per engine.

    Args:
        name: check to list.
        path: project folder (defaults to the working directory).
        severity: minimum severity to include.
        file: only paths matching this glob or prefix (e.g. "app/Http/**").
        offset: findings to skip per engine (pagination).
        limit: maximum findings per engine.
        false_positives: include those flagged as likely false positives.
    """
    return _compact(await checks.run_check(name, path, severity, file, offset, limit, false_positives))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
