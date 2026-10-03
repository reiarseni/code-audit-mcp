"""PHP / Laravel: dead code (PHPStan + shipmonk), dependencies (composer-unused,
composer-require-checker), vulnerabilities (composer audit) and lint (the project's own PHPStan).

Tools are installed in `~/.cache/code-audit-mcp/php/…`, never in the project's vendor/.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

from code_audit_mcp.core import (
    Context,
    Unit,
    engine_result,
    ensure_composer_tool,
    finding,
    is_test_path,
    parse_json,
    project_cache,
    read_json,
    require_bin,
    run,
    tool_failure,
)

PHP_HINT = "Install PHP CLI (8.2+)."

# Hooks that Laravel/Livewire/Filament invoke by convention.
FRAMEWORK_MEMBERS = {
    "__construct", "__invoke", "mount", "render", "boot", "booted", "booting", "hydrate", "dehydrate", "rules",
    "messages", "attributes", "validationAttributes", "getListeners", "placeholder", "rendering", "rendered",
    "handle", "authorize", "prepareForValidation", "passedValidation", "failedValidation", "toArray", "toMail",
    "toDatabase", "via", "viaQueue", "middleware", "failed", "tries", "backoff", "retryUntil", "definition",
    "configure", "casts", "register", "schedule", "commands", "form", "table", "infolist", "getPages",
    "getRelations", "getNavigationBadge", "canAccess", "getHeaderActions", "getHeaderWidgets", "getFooterWidgets",
    "getWidgets", "getColumns", "getData", "getType", "getOptions", "getHeading", "getStats", "getTitle",
    "getFormSchema", "getTableQuery", "getTableColumns", "getTableFilters", "getTableActions", "getActions",
    "shouldRegisterNavigation", "getNavigationGroup", "getNavigationLabel", "getEloquentQuery", "getModelLabel",
}
# Eloquent accessors/mutators/scopes and Livewire/trait lifecycle hooks.
_CONVENTION = re.compile(r"^((get|set)\w+Attribute|scope[A-Z]\w*|updat(ed|ing)[A-Z]\w*|(boot|initialize|mount)[A-Z]\w*)$")
_COMPONENT_HINTS = ("extends Component", "Livewire\\", "Filament\\", "extends Page", "extends Widget",
                    "extends Resource", "extends RelationManager")
_VIEW_REFERENCE = re.compile(r"(?:wire:[\w.-]+\s*=\s*\"\s*\$?|\$|->|::|@)(\w+)|(\w+)\s*\(")

DEAD_RULES = {
    "shipmonk.deadMethod": "unused-method",
    "shipmonk.deadConstant": "unused-constant",
    "shipmonk.deadEnumCase": "unused-enum-case",
    "shipmonk.deadProperty.neverRead": "property-never-read",
    "shipmonk.deadProperty.neverWritten": "property-never-written",
    "shipmonk.deadProperty": "unused-property",
    "shipmonk.deadClass": "unused-class",
}

# Global Laravel facade aliases (config/app.php → aliases).
LARAVEL_ALIASES = {
    "App", "Arr", "Artisan", "Auth", "Blade", "Broadcast", "Bus", "Cache", "Concurrency", "Config", "Context",
    "Cookie", "Crypt", "Date", "DB", "Eloquent", "Event", "Exceptions", "File", "Gate", "Hash", "Http", "Js",
    "Lang", "Log", "Mail", "Notification", "Number", "Password", "Process", "Queue", "RateLimiter", "Redirect",
    "Redis", "Request", "Response", "Route", "Schedule", "Schema", "Session", "Storage", "Str", "Uri", "URL",
    "Validator", "View", "Vite",
}


def php_bin() -> str:
    return require_bin("php", PHP_HINT, "CODE_AUDIT_PHP")


def installed_packages(unit: Unit) -> dict[str, dict[str, Any]]:
    data = read_json(unit.dir / "vendor" / "composer" / "installed.json")
    packages = data.get("packages", []) if isinstance(data, dict) else (data or [])
    return {p["name"]: p for p in packages if isinstance(p, dict) and "name" in p}


def no_vendor(engine: str, unit: Unit) -> dict[str, Any] | None:
    if not (unit.dir / "vendor" / "autoload.php").exists():
        return engine_result(engine, unit, skipped="vendor/ is missing: run `composer install` in the project")
    return None


def neon_list(items: list[str]) -> str:
    return "".join(f"\n    - '{i.replace(chr(39), chr(39) * 2)}'" for i in items)


# --------------------------------------------------------------------------- dead code
def dead_code_paths(unit: Unit) -> list[str]:
    candidates = ["app", "src", "lib", "routes", "database", "config", "tests", "bootstrap/app.php",
                  "bootstrap/providers.php"]
    return [str(unit.dir / c) for c in candidates if (unit.dir / c).exists()]


def view_references(unit: Unit) -> set[str]:
    """Identifiers used from Blade views (wire:click="x", $x, ->x, x(…))."""
    refs: set[str] = set()
    views = unit.dir / "resources" / "views"
    if views.is_dir():
        for file in views.rglob("*.blade.php"):
            try:
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for a, b in _VIEW_REFERENCE.findall(text):
                refs.add(a or b)
    return refs


def false_positive_reason(item: dict[str, Any], source: str, refs: set[str]) -> str | None:
    member = (item.get("name") or "").rsplit("::", 1)[-1].lstrip("$")
    if not member:
        return None
    if member in FRAMEWORK_MEMBERS:
        return "hook invoked by Laravel/Livewire/Filament convention"
    if member in refs:
        return "referenced from a Blade view"
    line_no = item.get("line") or 0
    lines = source.splitlines()
    line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    if "public" in line and any(h in source for h in _COMPONENT_HINTS):
        return "public member of a Livewire/Filament component (the view may use it)"
    if _CONVENTION.match(member):
        return "Eloquent accessor/mutator/scope or Livewire hook invoked by convention"
    return None


def parse_phpstan(data: dict[str, Any], ctx: Context, unit: Unit) -> list[dict[str, Any]]:
    out = []
    for file, info in (data.get("files") or {}).items():
        for m in info.get("messages", []):
            out.append({"file": ctx.rel(file, unit.dir), "line": m.get("line"), "identifier": m.get("identifier") or "",
                        "message": m.get("message", ""), "tip": m.get("tip")})
    return out


async def run_dead_code(unit: Unit, ctx: Context, with_larastan: bool) -> tuple[dict[str, Any], bool]:
    installed = installed_packages(unit)
    version = (installed.get("phpstan/phpstan") or {}).get("version", "").lstrip("v")
    # Same PHPStan as the project, so its Larastan is compatible.
    tool_name = f"deadcode-phpstan-{version}" if version else "deadcode-latest"
    phpstan = await ensure_composer_tool(
        tool_name, [f"phpstan/phpstan:{version}" if version else "phpstan/phpstan:^2", "shipmonk/dead-code-detector"],
        "phpstan",
    )
    includes = [str(phpstan.parent.parent / "shipmonk" / "dead-code-detector" / "rules.neon")]
    larastan = unit.dir / "vendor" / "larastan" / "larastan" / "extension.neon"
    used_larastan = with_larastan and larastan.exists()
    if used_larastan:
        includes.append(str(larastan))
    neon = (
        f"includes:{neon_list(includes)}\n"
        "parameters:\n  level: 0\n  reportUnmatchedIgnoredErrors: false\n"
        f"  paths:{neon_list(dead_code_paths(unit))}\n"
        f"  excludePaths:\n    analyseAndScan:{neon_list([str(unit.dir / 'bootstrap' / 'cache'), str(unit.dir / 'storage')])}\n"
        f"  bootstrapFiles:{neon_list([str(unit.dir / 'vendor' / 'autoload.php')])}\n"
        f"  tmpDir: '{project_cache('phpstan-deadcode', unit.dir)}'\n"
    )
    with tempfile.TemporaryDirectory(prefix="code-audit-") as tmp:
        config = Path(tmp) / "deadcode.neon"
        config.write_text(neon, encoding="utf-8")
        proc = await run([php_bin(), "-d", "memory_limit=-1", str(phpstan), "analyse", "-c", str(config),
                          "--error-format=json", "--no-progress", "--no-interaction"], cwd=unit.dir)
    if proc.returncode not in (0, 1):
        raise tool_failure("phpstan (dead code)", proc)
    return parse_json("phpstan", proc), used_larastan


def larastan_marker(unit: Unit) -> Path:
    installed = installed_packages(unit)
    versions = "-".join((installed.get(p) or {}).get("version", "none") for p in ("larastan/larastan", "phpstan/phpstan"))
    return project_cache("phpstan-deadcode", unit.dir) / f"larastan-broken-{versions}"


async def dead_code(unit: Unit, ctx: Context) -> dict[str, Any]:
    if (skip := no_vendor("phpstan+shipmonk", unit)) is not None:
        return skip
    notes = ["Tests count as usage, but are not reported."]
    marker = larastan_marker(unit)
    broken_note = "The project's Larastan causes an internal PHPStan error (incompatible versions); analysis runs without Larastan."
    if marker.exists():
        notes.append(broken_note)
    data, used_larastan = await run_dead_code(unit, ctx, with_larastan=not marker.exists())
    if data.get("errors") and used_larastan:
        marker.touch()  # next time it is skipped directly
        notes.append(broken_note)
        data, used_larastan = await run_dead_code(unit, ctx, with_larastan=False)
    if data.get("errors"):
        return engine_result("phpstan+shipmonk", unit, error="PHPStan failed: " + str(data["errors"][0])[:400])
    refs = view_references(unit)
    sources: dict[str, str] = {}
    findings = []
    for m in parse_phpstan(data, ctx, unit):
        if not m["identifier"].startswith("shipmonk.") or is_test_path(m["file"]):
            continue
        name = re.search(r"([\w\\]+::\$?\w+)", m["message"])
        message = m["message"] + (f" — {m['tip']}" if m.get("tip") and "transitively" in m["tip"] else "")
        item = finding(m["file"], m["line"], DEAD_RULES.get(m["identifier"], m["identifier"].removeprefix("shipmonk.")),
                       message, "low", name=name.group(1) if name else None)
        if m["file"] not in sources:
            try:
                sources[m["file"]] = (ctx.root / m["file"]).read_text(encoding="utf-8", errors="replace")
            except OSError:
                sources[m["file"]] = ""
        if reason := false_positive_reason(item, sources[m["file"]], refs):
            item["likely_false_positive"] = reason
        findings.append(item)
    if used_larastan:
        notes.append("With the project's Larastan.")
    return engine_result("phpstan+shipmonk", unit, findings, notes)


# --------------------------------------------------------------------------- dependencies
async def composer_unused(unit: Unit, ctx: Context) -> dict[str, Any]:
    if (skip := no_vendor("composer-unused", unit)) is not None:
        return skip
    tool = await ensure_composer_tool("composer-unused", ["icanhazstring/composer-unused"], "composer-unused")
    proc = await run([php_bin(), "-d", "memory_limit=-1", str(tool), "--output-format=json", "--no-progress"],
                     cwd=unit.dir)
    if proc.returncode not in (0, 1):
        raise tool_failure("composer-unused", proc)
    data = parse_json("composer-unused", proc, proc.stdout[proc.stdout.find("{"):])
    composer_rel = "composer.json" if unit.rel == "." else f"{unit.rel}/composer.json"
    findings = [
        finding(composer_rel, None, "unused-package", f"{name}: declared in composer.json but not used in the code",
                "medium", name=name)
        for name in data.get("unused-packages", [])
    ]
    return engine_result("composer-unused", unit, findings,
                         ["Packages used only through configuration or service providers may show up as unused."])


def psr_prefixes(installed: dict[str, dict[str, Any]]) -> list[tuple[str, str]]:
    prefixes = []
    for name, pkg in installed.items():
        autoload = pkg.get("autoload", {})
        for kind in ("psr-4", "psr-0"):
            for prefix in autoload.get(kind, {}) or {}:
                if prefix:
                    prefixes.append((prefix, name))
    return sorted(prefixes, key=lambda p: -len(p[0]))


def classify_symbols(symbols: dict[str, list[str]], composer: dict[str, Any],
                     installed: dict[str, dict[str, Any]], composer_rel: str) -> list[dict[str, Any]]:
    """Splits unknown symbols into transitive, development, Laravel aliases and nonexistent ones."""
    prefixes = psr_prefixes(installed)
    direct = set(composer.get("require", {}))
    dev = set(composer.get("require-dev", {}))
    own = tuple((composer.get("autoload", {}) or {}).get("psr-4", {}) or {})
    transitive: dict[str, list[str]] = {}
    dev_used: dict[str, list[str]] = {}
    findings = []
    ext_owners: dict[str, list[str]] = {}
    for name, info in installed.items():
        for req in info.get("require") or {}:
            if req.startswith("ext-"):
                ext_owners.setdefault(req, []).append(name)
    ext_used: dict[str, list[str]] = {}
    for symbol, guesses in symbols.items():
        if symbol in LARAVEL_ALIASES:
            continue
        exts = [g for g in guesses if g.startswith("ext-")]
        if exts and any(e in ext_owners for e in exts):
            ext_used.setdefault(next(e for e in exts if e in ext_owners), []).append(symbol)
            continue
        is_own = bool(own) and symbol.startswith(own)
        package = None if is_own else next((pkg for prefix, pkg in prefixes if symbol.startswith(prefix)), None)
        if package and package in dev:
            dev_used.setdefault(package, []).append(symbol)
        elif package and package not in direct:
            transitive.setdefault(package, []).append(symbol)
        elif package is None:
            hint = f" (missing {', '.join(guesses)}?)" if guesses else ""
            if is_own:
                message = f"{symbol}: the project's own class does not exist; probably a wrong import{hint}"
            elif "\\" not in symbol and symbol[:1].islower():
                message = f"{symbol}: unknown function/constant; maybe an undeclared PHP extension{hint}"
            else:
                message = f"{symbol}: symbol not provided by any installed package{hint}"
            findings.append(finding(composer_rel, None, "unknown-symbol", message, "medium", name=symbol))
    for package, used in sorted(dev_used.items()):
        findings.append(finding(composer_rel, None, "dev-package-in-production",
                                f"{package} is in require-dev but used in production code "
                                f"({len(used)} symbols, e.g. {used[0]})", "medium", name=package))
    for ext, used in sorted(ext_used.items()):
        owners = ", ".join(sorted(ext_owners[ext])[:3])
        findings.append(finding(composer_rel, None, "undeclared-extension",
                                f"{ext} is used directly ({len(used)} symbols, e.g. {used[0]}) but is not in "
                                f"composer.json; currently guaranteed by {owners}", "info", name=ext))
    for package, used in sorted(transitive.items()):
        via = sorted(p for p, info in installed.items() if p in direct and package in (info.get("require") or {}))
        findings.append(finding(composer_rel, None, "transitive-dependency",
                                f"{package} is used directly ({len(used)} symbols, e.g. {used[0]}) but only "
                                f"arrives as a dependency of {', '.join(via) or 'another package'}", "info", name=package))
    return findings


async def require_checker(unit: Unit, ctx: Context) -> dict[str, Any]:
    if (skip := no_vendor("composer-require-checker", unit)) is not None:
        return skip
    tool = await ensure_composer_tool("require-checker", ["maglnet/composer-require-checker"],
                                      "composer-require-checker")
    proc = await run([php_bin(), "-d", "memory_limit=-1", str(tool), "check", "--output=json",
                      str(unit.dir / "composer.json")], cwd=unit.dir)
    if proc.returncode not in (0, 1):
        raise tool_failure("composer-require-checker", proc)
    data = parse_json("composer-require-checker", proc, proc.stdout[proc.stdout.find("{"):])
    composer = read_json(unit.dir / "composer.json") or {}
    composer_rel = "composer.json" if unit.rel == "." else f"{unit.rel}/composer.json"
    findings = classify_symbols(data.get("unknown-symbols") or {}, composer, installed_packages(unit), composer_rel)
    return engine_result("composer-require-checker", unit, findings)


# --------------------------------------------------------------------------- vulnerabilities
def locked_versions(unit: Unit) -> dict[str, str]:
    lock = read_json(unit.dir / "composer.lock") or {}
    return {p["name"]: p.get("version", "?") for key in ("packages", "packages-dev") for p in lock.get(key, []) or []}


async def composer_audit(unit: Unit, ctx: Context) -> dict[str, Any]:
    if not (unit.dir / "composer.lock").exists():
        return engine_result("composer audit", unit, skipped="no composer.lock")
    composer = require_bin("composer", "Install Composer: https://getcomposer.org/", "CODE_AUDIT_COMPOSER")
    proc = await run([composer, "audit", "--format=json", "--locked", "--no-interaction"], cwd=unit.dir, timeout=180)
    if proc.returncode not in (0, 1, 2, 3):
        raise tool_failure("composer audit", proc)
    data = parse_json("composer audit", proc, proc.stdout[proc.stdout.find("{"):])
    versions = locked_versions(unit)
    lock_rel = "composer.lock" if unit.rel == "." else f"{unit.rel}/composer.lock"
    findings = []
    advisories = data.get("advisories") or {}
    for package, items in (advisories.items() if isinstance(advisories, dict) else []):
        for a in items.values() if isinstance(items, dict) else items:
            severity = (a.get("severity") or "high").lower()
            findings.append(finding(
                lock_rel, None, a.get("cve") or a.get("advisoryId", "advisory"),
                f"{package} {versions.get(package, '?')}: {a.get('title', '')} (affects {a.get('affectedVersions', '?')})",
                severity if severity in {"critical", "high", "medium", "low"} else "high",
                name=package, link=a.get("link"),
            ))
    for package, replacement in (data.get("abandoned") or {}).items():
        findings.append(finding(lock_rel, None, "abandoned-package",
                                f"{package} is abandoned" + (f"; use {replacement}" if replacement else ""),
                                "low", name=package))
    return engine_result("composer audit", unit, findings)


# --------------------------------------------------------------------------- lint
async def phpstan(unit: Unit, ctx: Context) -> dict[str, Any]:
    binary = unit.dir / "vendor" / "bin" / "phpstan"
    configs = [c for c in ("phpstan.neon", "phpstan.neon.dist", "phpstan.dist.neon") if (unit.dir / c).exists()]
    if not binary.exists() or not configs:
        return engine_result("phpstan", unit, skipped="the project does not have PHPStan installed and configured")
    proc = await run([php_bin(), "-d", "memory_limit=-1", str(binary), "analyse", "--error-format=json",
                      "--no-progress", "--no-interaction"], cwd=unit.dir)
    if proc.returncode not in (0, 1):
        raise tool_failure("phpstan", proc)
    data = parse_json("phpstan", proc, proc.stdout[proc.stdout.find("{"):])
    findings = [
        finding(configs[0] if unit.rel == "." else f"{unit.rel}/{configs[0]}", None, "phpstan-internal-error",
                f"The project's PHPStan fails: {str(e).splitlines()[0][:300]}", "high")
        for e in data.get("errors", [])[:3]
    ]
    findings += [
        finding(m["file"], m["line"], m["identifier"] or "phpstan", m["message"], "medium")
        for m in parse_phpstan(data, ctx, unit)
    ]
    notes = []
    if data.get("errors"):
        notes.append("With internal errors PHPStan does not analyze everything: the result is incomplete.")
    return engine_result("phpstan", unit, findings, notes)

