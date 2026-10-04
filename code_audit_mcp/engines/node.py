"""TypeScript / React / Next.js: knip (dead code and dependencies), npm/pnpm/bun audit, yarn.lock in OSV.dev
and the project's own tsc/eslint if it has node_modules.

knip and pnpm run through `npx -y` (npm cache); nothing is installed or written in the project.
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from code_audit_mcp.core import (
    Context,
    ToolRun,
    Unit,
    engine_result,
    finding,
    npx,
    parse_json,
    read_json,
    require_bin,
    run,
    tool_failure,
    which,
)
from code_audit_mcp.engines.shared import osv_findings, osv_query

KNIP = "knip@5"
KNIP_CONFIG_FILES = ("knip.json", "knip.jsonc", ".knip.json", ".knip.jsonc")
KNIP_CODE_CONFIGS = ("knip.ts", "knip.config.ts", "knip.js", "knip.config.js", "knip.mts", "knip.config.mjs")
_LOAD_ERROR = re.compile(r"Error loading (\S+)")
E2E_DIRS = {"e2e", "cypress", "playwright", "tests", "test"}

DEAD_KEYS = {
    "exports": ("unused-export", "unused export"),
    "types": ("unused-type", "unused exported type"),
    "nsExports": ("unused-export", "unused namespace export"),
    "nsTypes": ("unused-type", "unused namespace type"),
    "enumMembers": ("unused-enum-member", "unused enum member"),
    "classMembers": ("unused-class-member", "unused class member"),
    "duplicates": ("duplicate-export", "duplicate export"),
}
DEPENDENCY_KEYS = {
    "dependencies": ("unused-dependency", "medium", "declared in dependencies but unused"),
    "devDependencies": ("unused-devDependency", "low", "declared in devDependencies but unused"),
    "optionalPeerDependencies": ("unused-peerDependency", "low", "unused optional peer dependency"),
    "unlisted": ("unlisted-dependency", "medium", "imported but not listed in package.json"),
    "binaries": ("unlisted-binary", "low", "binary used in scripts that no dependency provides"),
    "unresolved": ("unresolved-import", "medium", "import that cannot be resolved"),
}


def has_node_modules(unit: Unit) -> bool:
    return (unit.dir / "node_modules").is_dir()


def plugin_from_config(path: str) -> str:
    """playwright.config.ts → playwright, .eslintrc.cjs → eslint, vite.config.mts → vite."""
    return re.sub(r"^\.?([a-z0-9-]+?)(rc)?\..*$", r"\1", Path(path).name)


_VITE_INPUT = re.compile(r"(?:input\s*:\s*|laravel\(\s*)(\[[^\]]*\]|['\"][^'\"]+['\"])", re.S)
_QUOTED = re.compile(r"['\"]([^'\"]+)['\"]")
_ENTRY_EXT = (".js", ".mjs", ".ts", ".jsx", ".tsx", ".vue")


def vite_inputs(unit: Unit) -> list[str]:
    """Entries declared in vite.config (laravel-vite-plugin) that exist in the project."""
    for name in ("vite.config.js", "vite.config.ts", "vite.config.mjs", "vite.config.mts"):
        file = unit.dir / name
        if file.exists():
            text = file.read_text(encoding="utf-8", errors="replace")
            found = [q for m in _VITE_INPUT.finditer(text) for q in _QUOTED.findall(m.group(1))]
            return [f for f in dict.fromkeys(found) if (unit.dir / f).exists()]
    return []


def project_knip_config(unit: Unit) -> tuple[dict[str, Any] | None, bool]:
    """(the project's JSON config, True if it has a code-based config we cannot merge)."""
    if any((unit.dir / c).exists() for c in KNIP_CODE_CONFIGS):
        return None, True
    for name in KNIP_CONFIG_FILES:
        if (unit.dir / name).exists():
            data = read_json(unit.dir / name)
            return (data if isinstance(data, dict) else {}), False
    package = read_json(unit.dir / "package.json") or {}
    return (package.get("knip") if isinstance(package.get("knip"), dict) else None), False


async def _knip(unit: Unit) -> tuple[dict[str, Any], list[str]]:
    """Runs knip; if loading a plugin config fails (no node_modules), disables it and retries."""
    base_config, code_config = project_knip_config(unit)
    entries = [e for e in vite_inputs(unit) if e.endswith(_ENTRY_EXT)]
    if entries and not code_config:  # knip does not understand laravel-vite-plugin entries
        base_config = {**(base_config or {}), "entry": [*(base_config or {}).get("entry", []), *entries]}
    disabled: list[str] = []
    cmd = npx(KNIP, "--reporter", "json", "--no-progress", "--no-exit-code")
    with tempfile.TemporaryDirectory(prefix="code-audit-") as tmp:
        cfg_path = Path(tmp) / "knip.json"
        proc: ToolRun | None = None
        for _ in range(10):
            extra: list[str] = []
            if disabled or entries:
                cfg = {**(base_config or {}), **{p: False for p in disabled}}
                cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
                extra = ["--config", str(cfg_path)]
            proc = await run([*cmd, *extra], cwd=unit.dir)
            try:
                return json.loads(proc.stdout), disabled
            except json.JSONDecodeError:
                pass
            failed = _LOAD_ERROR.search(proc.stderr + proc.stdout)
            if not failed or code_config:
                break
            plugin = plugin_from_config(failed.group(1))
            if plugin in disabled:
                break
            disabled.append(plugin)
    assert proc is not None
    raise tool_failure("knip", proc)


def knip_result(unit: Unit, ctx: Context) -> Any:
    return ctx.once(("knip", unit.dir), lambda: _knip(unit))


def _disabled_note(unit: Unit, disabled: list[str]) -> list[str]:
    notes = []
    if not has_node_modules(unit):
        notes.append("No node_modules: partial analysis. With `npm ci` (or equivalent) knip loads all plugins.")
    if disabled:
        notes.append(f"knip plugins disabled because their config fails to load: {', '.join(disabled)}.")
    return notes


def dead_from_knip(data: dict[str, Any], unit: Unit, ctx: Context, disabled: list[str]) -> list[dict[str, Any]]:
    findings = []
    inputs = set(vite_inputs(unit))
    for file in data.get("files", []):
        item = finding(ctx.rel(file, unit.dir), None, "unused-file", "file that nothing imports", "low",
                       name=Path(file).name)
        parts = Path(file).parts
        if any(Path(file).name.startswith(p + ".") for p in disabled) or (
            disabled and set(parts[:-1]) & E2E_DIRS
        ):
            item["likely_false_positive"] = "belongs to a disabled knip plugin (node_modules missing)"
        elif str(Path(file)) in inputs:
            item["likely_false_positive"] = "entry declared in vite.config (laravel-vite-plugin)"
        findings.append(item)
    for issue in data.get("issues", []):
        rel = ctx.rel(issue["file"], unit.dir)
        for key, (rule, label) in DEAD_KEYS.items():
            value = issue.get(key)
            if not value:
                continue
            if isinstance(value, dict):  # enumMembers / classMembers: {Container: [members]}
                entries = [(f"{owner}.{m['name']}", m) for owner, members in value.items() for m in members]
            elif key == "duplicates":
                entries = [(" = ".join(d["name"] for d in group), group[0]) for group in value]
            else:
                entries = [(m["name"], m) for m in value]
            for name, meta in entries:
                findings.append(finding(rel, meta.get("line"), rule, f"{label}: {name}", "low", name=name))
    return findings


async def knip_dead_code(unit: Unit, ctx: Context) -> dict[str, Any]:
    data, disabled = await knip_result(unit, ctx)
    return engine_result("knip", unit, dead_from_knip(data, unit, ctx, disabled), _disabled_note(unit, disabled))


async def knip_dependencies(unit: Unit, ctx: Context) -> dict[str, Any]:
    data, disabled = await knip_result(unit, ctx)
    findings = []
    for issue in data.get("issues", []):
        rel = ctx.rel(issue["file"], unit.dir)
        for key, (rule, severity, label) in DEPENDENCY_KEYS.items():
            for meta in issue.get(key) or []:
                findings.append(finding(rel, meta.get("line"), rule, f"{meta['name']}: {label}", severity,
                                        name=meta["name"]))
    return engine_result("knip", unit, findings, _disabled_note(unit, disabled))


# --------------------------------------------------------------------------- vulnerabilities
SEVERITY_MAP = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium", "low": "low",
                "info": "info"}


def parse_npm_audit(data: dict[str, Any], lock_rel: str) -> list[dict[str, Any]]:
    findings = []
    for name, vuln in (data.get("vulnerabilities") or {}).items():
        advisories = [v for v in vuln.get("via", []) if isinstance(v, dict)]
        if not advisories:
            continue  # only vulnerable through another package already reported
        fix = vuln.get("fixAvailable")
        fix_text = (f"upgrade {fix['name']} to {fix['version']}" + (" (major change)" if fix.get("isSemVerMajor") else "")
                    if isinstance(fix, dict) else ("`npm audit fix`" if fix else "no fix available"))
        titles = "; ".join(sorted({a.get("title", "") for a in advisories}))[:300]
        findings.append(finding(
            lock_rel, None, advisories[0].get("url", "").rsplit("/", 1)[-1] or "advisory",
            f"{name} (vulnerable: {vuln.get('range', '?')}): {titles}", SEVERITY_MAP.get(vuln.get("severity", ""), "high"),
            name=name, direct=bool(vuln.get("isDirect")) or None, fix=fix_text,
        ))
    return findings


def parse_bun_audit(data: dict[str, Any], lock_rel: str) -> list[dict[str, Any]]:
    findings = []
    for name, items in data.items():
        for a in items if isinstance(items, list) else []:
            findings.append(finding(
                lock_rel, None, a.get("url", "").rsplit("/", 1)[-1] or str(a.get("id", "advisory")),
                f"{name} (vulnerable: {a.get('vulnerable_versions', '?')}): {a.get('title', '')}",
                SEVERITY_MAP.get(a.get("severity", ""), "high"), name=name,
            ))
    return findings


def parse_pnpm_audit(data: dict[str, Any], lock_rel: str) -> list[dict[str, Any]]:
    findings = []
    for a in (data.get("advisories") or {}).values():
        findings.append(finding(
            lock_rel, None, a.get("github_advisory_id") or str(a.get("id", "advisory")),
            f"{a.get('module_name')} (vulnerable: {a.get('vulnerable_versions', '?')}): {a.get('title', '')}",
            SEVERITY_MAP.get(a.get("severity", ""), "high"), name=a.get("module_name"),
            fix=f"upgrade to {a['patched_versions']}" if a.get("patched_versions") else None,
        ))
    return findings


_YARN_VERSION = re.compile(r'^  version:? "?([^"\s]+)"?$')


def _yarn_package(spec: str) -> str | None:
    """Real package name from a descriptor (`lodash@^4`, `@a/b@npm:^1`, `alias@npm:real@^2`)."""
    at = spec.find("@", 1)
    if at == -1:
        return None
    name, version_range = spec[:at], spec[at + 1:]
    if version_range.startswith("npm:"):
        version_range = version_range[4:]
        if (alias_at := version_range.find("@", 1)) != -1:
            name, version_range = version_range[:alias_at], version_range[alias_at + 1:]
    return None if ":" in version_range else name  # workspace:, patch:, file:, git…: not in the registry


def parse_yarn_lock(text: str) -> list[tuple[str, str]]:
    """[(package, version)] from the npm registry in a yarn 1 or Berry yarn.lock."""
    packages: set[tuple[str, str]] = set()
    name = None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.endswith(":") and not line.startswith(("#", "__metadata")):
            name = _yarn_package(line[:-1].split(",")[0].strip().strip('"'))
        elif name and (m := _YARN_VERSION.match(line)):
            packages.add((name, m.group(1)))
            name = None
    return sorted(packages)


def _from_brace(text: str) -> str:
    start = text.find("{")
    return text[start:] if start != -1 else text


async def package_audit(unit: Unit, ctx: Context) -> dict[str, Any]:
    prefix = "" if unit.rel == "." else f"{unit.rel}/"
    if (unit.dir / "package-lock.json").exists():
        npm = require_bin("npm", "Install Node.js.", "CODE_AUDIT_NPM")
        proc = await run([npm, "audit", "--json", "--package-lock-only"], cwd=unit.dir, timeout=180)
        data = parse_json("npm audit", proc, _from_brace(proc.stdout))
        if "error" in data and not data.get("vulnerabilities"):
            raise tool_failure("npm audit", proc)
        return engine_result("npm audit", unit, parse_npm_audit(data, f"{prefix}package-lock.json"))
    if (unit.dir / "pnpm-lock.yaml").exists():
        cmd = [pnpm, "audit", "--json"] if (pnpm := which("pnpm")) else npx("pnpm@9", "audit", "--json")
        proc = await run(cmd, cwd=unit.dir, timeout=180)
        data = parse_json("pnpm audit", proc, _from_brace(proc.stdout))
        return engine_result("pnpm audit", unit, parse_pnpm_audit(data, f"{prefix}pnpm-lock.yaml"))
    if (unit.dir / "bun.lock").exists() or (unit.dir / "bun.lockb").exists():
        bun = which("bun", "CODE_AUDIT_BUN")
        if not bun:
            return engine_result("bun audit", unit, skipped="the project uses bun.lock but bun is not installed")
        proc = await run([bun, "audit", "--json"], cwd=unit.dir, timeout=180)
        data = parse_json("bun audit", proc, _from_brace(proc.stdout))
        lock = "bun.lock" if (unit.dir / "bun.lock").exists() else "bun.lockb"
        return engine_result("bun audit", unit, parse_bun_audit(data, f"{prefix}{lock}"))
    if (unit.dir / "yarn.lock").exists():
        packages = parse_yarn_lock((unit.dir / "yarn.lock").read_text(encoding="utf-8"))
        results = await osv_query("npm", packages)
        return engine_result("OSV.dev", unit, osv_findings(results, "npm", f"{prefix}yarn.lock"),
                             ["yarn.lock (yarn 1 or Berry) queried in OSV.dev: independent of the yarn version."])
    return engine_result("npm audit", unit, skipped="no lockfile (package-lock.json, pnpm-lock.yaml, bun.lock)")


# --------------------------------------------------------------------------- lint
TSC_LINE = re.compile(r"^(?P<file>.+?)\((?P<line>\d+),(?P<col>\d+)\): (?P<sev>error|warning) (?P<code>TS\d+): (?P<msg>.*)$")
ESLINT_CONFIGS = ("eslint.config.js", "eslint.config.mjs", "eslint.config.cjs", "eslint.config.ts",
                  ".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json", ".eslintrc.yml", ".eslintrc.yaml")


def tsconfig_targets(unit: Unit) -> list[str]:
    """tsconfig.json or, if it is a "solution" (files: [] + references), the referenced tsconfigs."""
    config = read_json(unit.dir / "tsconfig.json")
    if isinstance(config, dict) and config.get("files") == [] and config.get("references"):
        refs = []
        for ref in config["references"]:
            path = unit.dir / ref.get("path", "")
            path = path / "tsconfig.json" if path.is_dir() else path
            if path.exists():
                refs.append(str(path.relative_to(unit.dir)))
        return refs
    return ["tsconfig.json"]


async def tsc(unit: Unit, ctx: Context) -> dict[str, Any]:
    binary = unit.dir / "node_modules" / ".bin" / "tsc"
    if not (unit.dir / "tsconfig.json").exists():
        return engine_result("tsc", unit, skipped="no tsconfig.json")
    if not binary.exists():
        return engine_result("tsc", unit, skipped="no node_modules: install dependencies to type-check")
    findings = []
    with tempfile.TemporaryDirectory(prefix="code-audit-") as tmp:
        for i, config in enumerate(tsconfig_targets(unit)):
            # --tsBuildInfoFile in tmp: with `incremental`, tsc would write .tsbuildinfo in the project
            proc = await run([str(binary), "--noEmit", "--pretty", "false", "-p", config,
                              "--tsBuildInfoFile", str(Path(tmp) / f"{i}.tsbuildinfo")], cwd=unit.dir)
            if proc.returncode not in (0, 1, 2):
                raise tool_failure("tsc", proc)
            for line in proc.stdout.splitlines():
                if m := TSC_LINE.match(line.strip()):
                    findings.append(finding(ctx.rel(m["file"], unit.dir), int(m["line"]), m["code"], m["msg"],
                                            "medium" if m["sev"] == "error" else "low"))
    return engine_result("tsc", unit, findings)


async def eslint(unit: Unit, ctx: Context) -> dict[str, Any]:
    binary = unit.dir / "node_modules" / ".bin" / "eslint"
    if not any((unit.dir / c).exists() for c in ESLINT_CONFIGS):
        return engine_result("eslint", unit, skipped="the project has no eslint configuration")
    if not binary.exists():
        return engine_result("eslint", unit, skipped="no node_modules: install dependencies to run eslint")
    proc = await run([str(binary), ".", "-f", "json"], cwd=unit.dir)
    if proc.returncode not in (0, 1):
        raise tool_failure("eslint", proc)
    findings = [
        finding(ctx.rel(f["filePath"], unit.dir), m.get("line"), m.get("ruleId") or "parse-error", m["message"],
                "medium" if m.get("severity") == 2 else "low")
        for f in parse_json("eslint", proc, proc.stdout[proc.stdout.find("["):])
        for m in f.get("messages", [])
    ]
    return engine_result("eslint", unit, findings)
