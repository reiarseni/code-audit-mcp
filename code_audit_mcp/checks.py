"""Which engine resolves each check in each stack, and how they are run, filtered and summarized."""

from __future__ import annotations

import asyncio
import fnmatch
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from code_audit_mcp.config import load_config
from code_audit_mcp.core import SEVERITIES, AuditError, Context, Unit, engine_result, resolve_root
from code_audit_mcp.detect import detect_units
from code_audit_mcp.engines import dart, node, php, python, shared

UnitEngine = Callable[[Unit, Context], Awaitable[dict[str, Any]]]
RootEngine = Callable[[list[Unit], Context], Awaitable[dict[str, Any]]]

CHECKS: dict[str, str] = {
    "dead_code": "dead code: unused functions, methods, classes, exports and files",
    "dependencies": "dependencies declared but unused, used but undeclared, or transitive",
    "security": "code vulnerabilities: SQL injection, XSS, secrets (also in git history), "
                "Redis, insecure configuration",
    "vulnerabilities": "known CVEs in the installed dependencies",
    "complexity": "functions with high cyclomatic complexity",
    "lint": "lint and type errors using the project configuration",
}

UNIT_ENGINES: dict[str, dict[str, list[UnitEngine]]] = {
    "dead_code": {"python": [python.vulture], "php": [php.dead_code], "node": [node.knip_dead_code]},
    "dependencies": {"python": [python.deptry], "php": [php.composer_unused, php.require_checker],
                     "node": [node.knip_dependencies]},
    "security": {"python": [python.bandit]},
    "vulnerabilities": {"python": [python.pip_audit], "php": [php.composer_audit], "node": [node.package_audit],
                        "dart": [dart.osv_audit]},
    "complexity": {"python": [shared.lizard], "php": [shared.lizard], "node": [shared.lizard]},
    "lint": {"python": [python.ruff], "php": [php.phpstan], "node": [node.tsc, node.eslint], "dart": [dart.analyze]},
}
ROOT_ENGINES: dict[str, list[RootEngine]] = {"security": [shared.semgrep, shared.sensitive_files, shared.gitleaks]}

ENGINE_NAMES = {
    python.vulture: "vulture", php.dead_code: "phpstan+shipmonk", node.knip_dead_code: "knip",
    python.deptry: "deptry", php.composer_unused: "composer-unused", php.require_checker: "composer-require-checker",
    node.knip_dependencies: "knip", python.bandit: "bandit", python.pip_audit: "pip-audit",
    php.composer_audit: "composer audit", node.package_audit: "npm audit", shared.lizard: "lizard",
    python.ruff: "ruff", php.phpstan: "phpstan", node.tsc: "tsc", node.eslint: "eslint",
    shared.semgrep: "semgrep", shared.sensitive_files: "git", shared.gitleaks: "gitleaks",
    dart.osv_audit: "OSV.dev", dart.analyze: "dart analyze",
}

PAGE_SIZE = 50
TOP_PER_ENGINE = 5


def _rank(item: dict[str, Any]) -> tuple[int, int, str, int]:
    severity = item.get("severity", "low")
    return (
        "likely_false_positive" in item,
        SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES),
        item.get("file") or "",
        item.get("line") or 0,
    )


async def _guarded(name: str, unit: Unit | None, coro: Awaitable[dict[str, Any]]) -> dict[str, Any]:
    try:
        return await coro
    except AuditError as exc:
        return engine_result(name, unit, error=str(exc))
    except Exception as exc:  # a broken engine must not take down the rest of the audit
        return engine_result(name, unit, error=f"{type(exc).__name__}: {exc}")


def _shared_messages(findings: list[dict[str, Any]]) -> dict[str, str]:
    """Moves to `rules` the message of rules that repeat it identically in all their findings (semgrep, bandit…)."""
    messages: dict[str, set[str]] = {}
    counts: Counter[str] = Counter()
    for f in findings:
        messages.setdefault(f["rule"], set()).add(f.get("message", ""))
        counts[f["rule"]] += 1
    shared = {rule: next(iter(m)) for rule, m in messages.items() if len(m) == 1 and counts[rule] > 1}
    for f in findings:
        if f["rule"] in shared:
            del f["message"]
    return shared


def _postprocess(result: dict[str, Any], ctx: Context, page: Page) -> dict[str, Any]:
    if "findings" not in result:
        return result
    findings = [f for f in result["findings"] if not ctx.config.is_ignored(f) and page.accepts(f)]
    findings.sort(key=_rank)
    result["count"] = len(findings)
    fps = sum("likely_false_positive" in f for f in findings)
    if fps:
        result["likely_false_positives"] = fps
        if not page.false_positives:
            findings = [f for f in findings if "likely_false_positive" not in f]
    shown = findings[page.offset:page.offset + page.limit] if page.limit else findings
    if page.limit and len(findings) > page.offset + page.limit:
        result["truncated"] = len(findings) - page.offset - page.limit
        result["by_rule"] = dict(Counter(f["rule"] for f in findings).most_common(8))
    if rules := _shared_messages(shown):
        result["rules"] = rules
    result["findings"] = shown
    return result


@dataclass(frozen=True)
class Page:
    """Filters and pagination of `check`; `limit=0` returns everything (used by `audit` before summarizing)."""

    limit: int = 0
    offset: int = 0
    min_severity: str = "info"
    file: str = ""
    false_positives: bool = True

    def accepts(self, item: dict[str, Any]) -> bool:
        severity = item.get("severity", "low")
        if severity in SEVERITIES and SEVERITIES.index(severity) > SEVERITIES.index(self.min_severity):
            return False
        return not self.file or fnmatch.fnmatchcase(item.get("file") or "", self.file) or (
            item.get("file") or "").startswith(self.file.rstrip("*/") + "/")


async def _run_check(name: str, units: list[Unit], ctx: Context, page: Page) -> list[dict[str, Any]]:
    tasks = []
    for unit in units:
        for engine in UNIT_ENGINES.get(name, {}).get(unit.stack, []):
            tasks.append(_guarded(ENGINE_NAMES[engine], unit, engine(unit, ctx)))
    for engine in ROOT_ENGINES.get(name, []):
        tasks.append(_guarded(ENGINE_NAMES[engine], None, engine(units, ctx)))
    results = await asyncio.gather(*tasks)
    return [_postprocess(r, ctx, page) for r in results]


def _prepare(path: str) -> tuple[Context, list[Unit]]:
    root = resolve_root(path)
    ctx = Context(root=root, config=load_config(root))
    units = detect_units(root)
    if not units:
        raise AuditError(f"No Python, PHP, Node or Dart/Flutter project detected in {root}")
    return ctx, units


def _header(ctx: Context, units: list[Unit]) -> dict[str, Any]:
    out: dict[str, Any] = {"root": str(ctx.root), "stacks": [u.name for u in units]}
    if ctx.config.source:
        out["config"] = ctx.config.source
    if ctx.config.warnings:
        out["warnings"] = ctx.config.warnings
    return out


async def run_check(name: str, path: str = ".", severity: str = "info", file: str = "", offset: int = 0,
                    limit: int = PAGE_SIZE, false_positives: bool = False) -> dict[str, Any]:
    if name not in CHECKS:
        raise AuditError(f"Unknown check: {name}. Available: {', '.join(CHECKS)}")
    if severity not in SEVERITIES:
        raise AuditError(f"Unknown severity: {severity}. Use one of: {', '.join(SEVERITIES)}")
    ctx, units = _prepare(path)
    page = Page(limit=max(1, limit), offset=max(0, offset), min_severity=severity, file=file,
                false_positives=false_positives)
    results = await _run_check(name, units, ctx, page)
    out = {**_header(ctx, units), "check": name, "total": sum(r.get("count", 0) for r in results),
           "results": results}
    hints = []
    if any("truncated" in r for r in results):
        hints.append(f"There is more: offset={page.offset + page.limit} for the next page, or narrow down with severity/file.")
    if not false_positives and any(r.get("likely_false_positives") for r in results):
        hints.append("Likely false positives are omitted: pass false_positives=true to see them.")
    if hints:
        out["next"] = " ".join(hints)
    return out


def _brief(result: dict[str, Any]) -> dict[str, Any]:
    brief = {k: v for k, v in result.items() if k in ("engine", "unit", "error", "skipped", "count",
                                                      "likely_false_positives", "notes")}
    if "findings" in result:
        top = [f for f in result["findings"] if "likely_false_positive" not in f][:TOP_PER_ENGINE]
        if rules := {r: m for r, m in result.get("rules", {}).items() if any(f["rule"] == r for f in top)}:
            brief["rules"] = rules
        if result["count"] > len(top):
            brief["by_rule"] = dict(Counter(f["rule"] for f in result["findings"]).most_common(8))
        brief["top"] = top
    return brief


async def run_audit(path: str = ".") -> dict[str, Any]:
    ctx, units = _prepare(path)
    names = list(CHECKS)
    per_check = await asyncio.gather(*(_run_check(n, units, ctx, Page()) for n in names))
    report: dict[str, Any] = {**_header(ctx, units), "summary": {}, "checks": {}}
    severities: Counter[str] = Counter()
    for name, results in zip(names, per_check, strict=True):
        report["checks"][name] = [_brief(r) for r in results]
        counts = {r["unit"] + " · " + r["engine"]: r["count"] for r in results if "count" in r}
        failed = [f"{r['unit']} · {r['engine']}" for r in results if "error" in r]
        fps = sum(r.get("likely_false_positives", 0) for r in results)
        report["summary"][name] = {"total": sum(counts.values()), "per_engine": counts}
        if fps:
            report["summary"][name]["likely_false_positives"] = fps
        if failed:
            report["summary"][name]["failed"] = failed
        for r in results:
            for f in r.get("findings", []):
                if "likely_false_positive" not in f:
                    severities[f["severity"]] += 1
    report["severity_totals"] = {s: severities[s] for s in SEVERITIES if severities[s]}
    report["next"] = "Use check(name) to see the full list for a check."
    return report
