"""Dart / Flutter: pubspec.lock CVEs queried in OSV.dev and dart analyze with the project's analysis_options.yaml.
Security is covered by semgrep (own Flutter/Android/iOS rules) and the git engines.

dart analyze needs `.dart_tool/package_config.json`; generating it would require `pub get`, which writes to the
project, so it is skipped without it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from code_audit_mcp.core import (
    JUNK_DIRS,
    Context,
    Unit,
    engine_result,
    finding,
    parse_json,
    run,
    tool_failure,
    which,
)
from code_audit_mcp.engines.shared import osv_findings, osv_query

ANALYZE_SEVERITY = {"ERROR": "medium", "WARNING": "low", "INFO": "info"}

_LOCK_PACKAGE = re.compile(r"^  (\S+):$")
_LOCK_FIELD = re.compile(r'^    (dependency|source|version): "?([^"\s]+)"?')


def parse_pubspec_lock(text: str) -> tuple[list[tuple[str, str]], set[str]]:
    """([(package, version)] from pub.dev, {direct dependencies}); git, path and sdk are not in OSV."""
    entries: dict[str, dict[str, str]] = {}
    current = None
    in_packages = False
    for line in text.splitlines():
        if not line.startswith(" "):
            in_packages = line.startswith("packages:")
            current = None
        elif in_packages and (m := _LOCK_PACKAGE.match(line)):
            current = entries.setdefault(m.group(1), {})
        elif current is not None and (m := _LOCK_FIELD.match(line)):
            current[m.group(1)] = m.group(2)
    hosted = {name: e for name, e in entries.items() if e.get("source") == "hosted" and e.get("version")}
    return ([(name, e["version"]) for name, e in hosted.items()],
            {name for name, e in hosted.items() if e.get("dependency", "").startswith("direct")})


def pubspec_locks(unit: Unit) -> list[Path]:
    """pubspec.lock of the unit and of its nested packages (packages/*, example/…)."""
    return sorted(p for p in unit.dir.rglob("pubspec.lock")
                  if not any(part in JUNK_DIRS or part.startswith(".") for part in p.relative_to(unit.dir).parts[:-1]))


async def osv_audit(unit: Unit, ctx: Context) -> dict[str, Any]:
    locks = pubspec_locks(unit)
    if not locks:
        return engine_result("OSV.dev", unit, skipped="no pubspec.lock (run `flutter pub get`)")
    findings = []
    for lock in locks:
        packages, direct = parse_pubspec_lock(lock.read_text(encoding="utf-8"))
        findings += osv_findings(await osv_query("Pub", packages), "Pub", ctx.rel(lock), direct)
    return engine_result("OSV.dev", unit, findings,
                         ["Source: " + ", ".join(ctx.rel(p) for p in locks) + ". Pub has few published advisories: "
                          "0 findings does not guarantee there are no vulnerabilities."])


# --------------------------------------------------------------------------- dart analyze
def dart_binary(unit: Unit) -> str | None:
    """The Flutter SDK's dart in Flutter projects (the standalone one may not match in version)."""
    if explicit := os.environ.get("CODE_AUDIT_DART"):
        return explicit
    flutter = which("flutter", "CODE_AUDIT_FLUTTER")
    flutter_dart = Path(flutter).resolve().parent / "dart" if flutter else None
    if flutter_dart and flutter_dart.exists() and (unit.label == "Flutter" or not which("dart")):
        return str(flutter_dart)
    return which("dart")


def parse_dart_analyze(data: dict[str, Any], ctx: Context) -> list[dict[str, Any]]:
    findings = []
    for d in data.get("diagnostics", []):
        location = d.get("location", {})
        findings.append(finding(
            ctx.rel(location.get("file", "")), location.get("range", {}).get("start", {}).get("line"),
            d.get("code", "dart"), d.get("problemMessage", ""), ANALYZE_SEVERITY.get(d.get("severity", ""), "low"),
            fix=d.get("correctionMessage"),
        ))
    return findings


async def analyze(unit: Unit, ctx: Context) -> dict[str, Any]:
    if not (unit.dir / ".dart_tool" / "package_config.json").exists():
        return engine_result("dart analyze", unit,
                             skipped="no .dart_tool/: run `flutter pub get` (or `dart pub get`) to analyze")
    dart = dart_binary(unit)
    if not dart:
        return engine_result("dart analyze", unit, skipped="neither `dart` nor `flutter` found in PATH")
    proc = await run([dart, "analyze", "--format=json", "."], cwd=unit.dir)
    if proc.returncode not in (0, 1, 2, 3):
        raise tool_failure("dart analyze", proc)
    start = proc.stdout.find("{")
    if start == -1:
        if "No issues found" in proc.stdout:
            return engine_result("dart analyze", unit, [])
        raise tool_failure("dart analyze", proc)
    findings = parse_dart_analyze(parse_json("dart analyze", proc, proc.stdout[start:]), ctx)
    return engine_result("dart analyze", unit, findings)
