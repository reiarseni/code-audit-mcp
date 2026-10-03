"""Python (FastAPI, Flask, scripts): vulture, deptry, bandit, pip-audit and ruff via uvx.

From the project venv only package metadata and `uv pip freeze` are read.
"""

from __future__ import annotations

import ast
import json
import re
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from code_audit_mcp.core import (
    TEST_DIR_NAMES,
    Context,
    Unit,
    engine_result,
    finding,
    is_test_path,
    parse_json,
    require_bin,
    run,
    source_children,
    tool_failure,
    uvx,
)

DEV_GROUP_NAMES = {"dev", "develop", "test", "tests", "testing", "lint", "docs", "typing", "qa"}

# Methods/attributes that frameworks invoke by convention (vulture does not see them as used).
FRAMEWORK_HOOK_NAMES = {
    "compose", "on_mount", "on_unmount", "on_load", "on_resize", "get_default_screen", "BINDINGS", "CSS",
    "CSS_PATH", "DEFAULT_CSS", "COMMANDS", "SCREENS", "TITLE", "SUB_TITLE", "border_title", "border_subtitle",
    "model_config", "Config", "Meta", "setUp", "tearDown", "setUpClass", "tearDownClass", "__post_init__",
    "lifespan", "startup", "shutdown", "dispatch", "orm_mode", "from_attributes", "__tablename__",
    "__table_args__", "__abstract__",
}
ALEMBIC_NAMES = {"revision", "down_revision", "branch_labels", "depends_on", "upgrade", "downgrade"}
# Classes whose attributes are used by serialization/ORM even if nobody reads them explicitly.
MODEL_BASES = {
    "BaseModel", "BaseSettings", "Base", "DeclarativeBase", "SQLModel", "TypedDict", "NamedTuple", "Enum",
    "StrEnum", "IntEnum", "Schema", "Model", "Document", "RootModel",
}
FRAMEWORK_HOOK_PREFIXES = ("on_", "action_", "watch_", "validate_", "compute_", "test_", "visit_")
IGNORED_DECORATORS = {
    "property", "staticmethod", "classmethod", "cache", "lru_cache", "cached_property", "override",
    "overload", "abstractmethod", "wraps", "dataclass",
}


def find_venv_python(project: Path) -> Path | None:
    for name in (".venv", "venv", "env"):
        for rel in ("bin/python", "Scripts/python.exe"):
            cand = project / name / rel
            if cand.exists():
                return cand
    return None


def load_pyproject(project: Path) -> dict[str, Any]:
    file = project / "pyproject.toml"
    if not file.exists():
        return {}
    try:
        return tomllib.loads(file.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return {}


def python_targets(unit: Unit) -> list[Path]:
    """Top-level packages and modules with Python code (tests included: they count as usage)."""
    if (unit.dir / "__init__.py").exists():
        return [unit.dir]
    targets = []
    for child in source_children(unit.dir):
        if child.is_file() and child.suffix == ".py":
            targets.append(child)
        elif child.is_dir() and next((p for p in child.rglob("*.py") if "node_modules" not in p.parts), None):
            targets.append(child)
    return targets


# --------------------------------------------------------------------------- vulture
VULTURE_LINE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+): (?P<message>.+?) \((?P<confidence>\d+)% confidence(?:, (?P<size>\d+) lines?)?\)$"
)


def parse_vulture(output: str, base: Path, ctx: Context) -> list[dict[str, Any]]:
    findings = []
    for line in output.splitlines():
        m = VULTURE_LINE.match(line.strip())
        if not m:
            continue
        message = m["message"]
        name = re.search(r"'([^']+)'", message)
        kind = message.split(" '", 1)[0]
        findings.append(finding(
            ctx.rel(m["file"], base), int(m["line"]), kind.replace(" ", "-"), message,
            "low", name=name.group(1) if name else None, confidence=int(m["confidence"]),
        ))
    return findings


def source_index(source: str) -> tuple[dict[int, list[str]], set[int]]:
    """(line of each `def`/`class` and of its first decorator -> non-trivial decorators,
    lines of attributes of model classes: Pydantic, SQLAlchemy, dataclasses, Enum, TypedDict)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}, set()
    decorators: dict[int, list[str]] = {}
    fields: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.decorator_list:
            names = []
            for deco in node.decorator_list:
                target = deco.func if isinstance(deco, ast.Call) else deco
                name = ast.unparse(target)
                if name.rsplit(".", 1)[-1] not in IGNORED_DECORATORS:
                    names.append(name)
            if names:
                # vulture reports the line of the first decorator; the `def` too in case that changes
                decorators[node.lineno] = decorators[node.decorator_list[0].lineno] = names
        if isinstance(node, ast.ClassDef):
            bases = {ast.unparse(b).split("[", 1)[0].rsplit(".", 1)[-1] for b in node.bases}
            is_dataclass = any("dataclass" in ast.unparse(d) for d in node.decorator_list)
            if is_dataclass or bases & MODEL_BASES or any(b.endswith(("Model", "Schema", "Base")) for b in bases):
                for stmt in node.body:
                    if isinstance(stmt, (ast.AnnAssign, ast.Assign)):
                        fields.add(stmt.lineno)
    return decorators, fields


def annotate_false_positives(findings: list[dict[str, Any]], root: Path) -> None:
    """Flags implicit usages: FastAPI/Flask routes and other registration decorators, model fields,
    Alembic migrations and framework hooks."""
    cache: dict[str, tuple[dict[int, list[str]], set[int]]] = {}
    for f in findings:
        name = f.get("name") or ""
        if f["file"] not in cache:
            try:
                cache[f["file"]] = source_index((root / f["file"]).read_text(encoding="utf-8"))
            except OSError:
                cache[f["file"]] = ({}, set())
        decorators, fields = cache[f["file"]]
        reason = None
        if f["rule"] in {"unused-function", "unused-method", "unused-class", "unused-property"}:
            if decos := decorators.get(f["line"]):
                reason = f"registered by decorator @{decos[0]}"
        if reason is None and f["rule"] in {"unused-variable", "unused-attribute"} and f["line"] in fields:
            reason = "model field (Pydantic/SQLAlchemy/dataclass/Enum): used when serializing or in the ORM"
        if reason is None and name in ALEMBIC_NAMES and "versions" in Path(f["file"]).parts:
            reason = "Alembic migration: run by alembic by convention"
        if reason is None and (name in FRAMEWORK_HOOK_NAMES or name.startswith(FRAMEWORK_HOOK_PREFIXES)):
            reason = "hook/attribute invoked by framework convention"
        if reason:
            f["likely_false_positive"] = reason


async def vulture(unit: Unit, ctx: Context) -> dict[str, Any]:
    targets = python_targets(unit)
    if not targets:
        return engine_result("vulture", unit, skipped="no Python code")
    whitelists = [p for p in (unit.dir / "whitelist.py", unit.dir / "vulture_whitelist.py") if p.exists()]
    args = [*map(str, targets), *map(str, whitelists), "--min-confidence", str(ctx.config.min_confidence)]
    if ctx.config.ignore_decorators:
        args += ["--ignore-decorators", ",".join(ctx.config.ignore_decorators)]
    proc = await run(uvx("vulture", *args), cwd=unit.dir)
    if proc.returncode not in (0, 3):  # 3 = dead code found
        raise tool_failure("vulture", proc)
    findings = [f for f in parse_vulture(proc.stdout, unit.dir, ctx) if not is_test_path(f["file"])]
    annotate_false_positives(findings, ctx.root)
    notes = ["Tests count as usage, but are not reported."]
    if whitelists:
        notes.append("Whitelist applied: " + ", ".join(w.name for w in whitelists))
    return engine_result("vulture", unit, findings, notes)


# --------------------------------------------------------------------------- deptry
PACKAGE_MAP_SNIPPET = r"""
import importlib.metadata as m, json
inv = {}
for mod, dists in m.packages_distributions().items():
    if not mod.isidentifier() or mod.startswith("_"):
        continue
    for d in dists:
        inv.setdefault(d.lower().replace("_", "-").replace(".", "-"), set()).add(mod)
print(json.dumps({k: sorted(v) for k, v in inv.items()}))
"""

DEPTRY_RULES = {
    "DEP001": ("missing-dependency", "medium", "imported but not declared"),
    "DEP002": ("unused-dependency", "medium", "declared but not imported"),
    "DEP003": ("transitive-dependency", "low", "imported but only a transitive dependency"),
    "DEP004": ("dev-dependency-in-production", "medium", "development dependency used in production code"),
    "DEP005": ("stdlib-declared", "low", "stdlib package declared as a dependency"),
}


# Packages whose module has a different name (for when there is no venv to read the real map from).
COMMON_MODULE_MAP = {
    "pyjwt": ["jwt"], "python-jose": ["jose"], "pyyaml": ["yaml"], "python-dotenv": ["dotenv"],
    "pillow": ["PIL"], "beautifulsoup4": ["bs4"], "scikit-learn": ["sklearn"], "opencv-python": ["cv2"],
    "opencv-python-headless": ["cv2"], "psycopg2-binary": ["psycopg2"], "psycopg-binary": ["psycopg"],
    "psycopg": ["psycopg"], "python-dateutil": ["dateutil"], "pymupdf": ["fitz"], "python-magic": ["magic"],
    "python-slugify": ["slugify"], "google-generativeai": ["google"], "google-genai": ["google"],
    "msgpack-python": ["msgpack"], "pyzmq": ["zmq"], "attrs": ["attr", "attrs"], "markdown": ["markdown"],
    "python-docx": ["docx"], "python-pptx": ["pptx"], "faiss-cpu": ["faiss"], "sentence-transformers":
    ["sentence_transformers"], "redis": ["redis"], "pydantic-settings": ["pydantic_settings"],
    "email-validator": ["email_validator"], "flask-sqlalchemy": ["flask_sqlalchemy"], "flask-cors": ["flask_cors"],
    "flask-login": ["flask_login"], "flask-migrate": ["flask_migrate"], "flask-jwt-extended": ["flask_jwt_extended"],
}
# Used without importing them: DB drivers chosen by the connection URL, FastAPI/Pydantic extras, CLIs.
IMPLICIT_PACKAGES = {
    "asyncpg", "psycopg", "psycopg2", "psycopg2-binary", "psycopg-binary", "aiosqlite", "pymysql", "aiomysql",
    "mysqlclient", "python-multipart", "email-validator", "uvicorn", "gunicorn", "hypercorn", "alembic",
    "bcrypt", "hiredis", "uvloop", "httptools", "watchfiles", "websockets", "greenlet", "celery", "rq",
    "python-jose", "cryptography", "itsdangerous", "jinja2", "orjson", "ujson",
}


def dev_groups(pyproject: dict[str, Any]) -> list[str]:
    optional = pyproject.get("project", {}).get("optional-dependencies", {})
    return [g for g in optional if g.lower() in DEV_GROUP_NAMES]


def group_deptry(raw: list[dict[str, Any]], unit_rel: str) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for v in raw:
        code = v["error"]["code"]
        rule, severity, meaning = DEPTRY_RULES.get(code, (code, "low", v["error"]["message"]))
        entry = grouped.setdefault((code, v["module"]), finding(
            None, None, rule, f"{v['module']}: {meaning}", severity, name=v["module"], code=code,
        ))
        loc = v.get("location") or {}
        file = loc.get("file") or ""
        path = file if unit_rel == "." else f"{unit_rel}/{file}"
        if file.endswith(("pyproject.toml", "requirements.txt", "setup.py")):
            entry["file"] = entry["file"] or path
        elif file:
            entry.setdefault("locations", []).append(f"{path}:{loc.get('line')}")
    out = list(grouped.values())
    for e in out:
        if "locations" in e:
            e["occurrences"] = len(e["locations"])
            e["file"], e["line"] = e["locations"][0].rsplit(":", 1)[0], int(e["locations"][0].rsplit(":", 1)[1])
            e["locations"] = e["locations"][:5]
    return sorted(out, key=lambda e: (e["code"], e["name"]))


async def deptry(unit: Unit, ctx: Context) -> dict[str, Any]:
    venv_python = find_venv_python(unit.dir)
    notes: list[str] = []
    args = [".", "--no-ansi"]  # relative: deptry's exclusion regexes (tests, venvs) are relative
    first_party = sorted({
        c.name for base in (unit.dir, unit.dir / "src") if base.is_dir()
        for c in base.iterdir() if (c / "__init__.py").exists() or (c.suffix == ".py" and c.parent == base / "src")
    })
    for module in first_party:
        args += ["--known-first-party", module]
    groups = dev_groups(load_pyproject(unit.dir))
    if groups:
        args += ["--optional-dependencies-dev-groups", ",".join(groups)]
    if venv_python:
        proc = await run([str(venv_python), "-I", "-c", PACKAGE_MAP_SNIPPET], cwd=unit.dir, timeout=60)
        if proc.returncode == 0:
            mapping = json.loads(proc.stdout)
            args += ["--package-module-name-map", ",".join(f"{d}={'|'.join(m)}" for d, m in sorted(mapping.items()))]
    else:
        args += ["--package-module-name-map", ",".join(f"{d}={'|'.join(m)}" for d, m in COMMON_MODULE_MAP.items())]
        notes.append("No venv in the project: module names are inferred (common-package map + package "
                     "name); some false positives are possible.")
    with tempfile.TemporaryDirectory(prefix="code-audit-") as tmp:
        report = Path(tmp) / "deptry.json"
        proc = await run(uvx("deptry", *args, "--json-output", str(report)), cwd=unit.dir)
        if proc.returncode not in (0, 1) or not report.exists():
            raise tool_failure("deptry", proc)
        raw = json.loads(report.read_text(encoding="utf-8") or "[]")
    findings = group_deptry(raw, unit.rel)
    for f in findings:
        if f["rule"] == "unused-dependency" and f["name"].lower() in IMPLICIT_PACKAGES:
            f["likely_false_positive"] = "used without importing it (DB driver by URL, FastAPI/Pydantic extra or CLI)"
    return engine_result("deptry", unit, findings, notes)


# --------------------------------------------------------------------------- bandit
_PASSWORD_VALUE = re.compile(r"Possible hardcoded password: '(.*)'")


def looks_like_secret(value: str) -> bool:
    """False for values that cannot be a real password (HEAD, 'refresh_token:', 'password')."""
    if len(value) < 8 or " " in value or value.startswith(("refs/", "http", "/", "$", "{")):
        return False
    if re.fullmatch(r"[A-Z0-9_]+|[a-z_]+|[\w.-]*[:_/.-]", value):
        return False
    return len(set(value)) >= 6  # minimum entropy


def literal_command_lines(source: str) -> set[int]:
    """Lines with calls whose first argument is a list/tuple of literals (`["git", "status"]`)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
            elts = node.args[0].elts
            if elts and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in elts):
                lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return lines


def annotate_bandit(findings: list[dict[str, Any]], root: Path) -> None:
    sources: dict[str, set[int]] = {}
    for f in findings:
        reason = None
        if f["rule"] == "B404":
            reason = "importing subprocess is not a vulnerability by itself"
        elif f["rule"] in {"B105", "B106", "B107"}:
            value = _PASSWORD_VALUE.search(f["message"])
            if value and not looks_like_secret(value.group(1)):
                reason = f"'{value.group(1)}' does not look like a credential (reference, prefix or constant)"
        elif f["rule"] in {"B603", "B607"}:
            if f["file"] not in sources:
                try:
                    sources[f["file"]] = literal_command_lines((root / f["file"]).read_text(encoding="utf-8"))
                except OSError:
                    sources[f["file"]] = set()
            if f["line"] in sources[f["file"]]:
                reason = "command with literal arguments: there is no external input to inject"
        if reason:
            f["likely_false_positive"] = reason


async def bandit(unit: Unit, ctx: Context) -> dict[str, Any]:
    targets = [t for t in python_targets(unit) if t.name not in TEST_DIR_NAMES and not is_test_path(ctx.rel(t))]
    if not targets:
        return engine_result("bandit", unit, skipped="no Python code")
    args = ["-r", *map(str, targets), "-f", "json", "-q", "-x", "*/tests/*,*/test_*.py,*_test.py,*/conftest.py"]
    if "bandit" in load_pyproject(unit.dir).get("tool", {}):
        args += ["-c", str(unit.dir / "pyproject.toml")]
    proc = await run(uvx("bandit[toml]", *args), cwd=unit.dir)
    if proc.returncode not in (0, 1):
        raise tool_failure("bandit", proc)
    data = parse_json("bandit", proc)
    findings = [
        finding(ctx.rel(r["filename"], unit.dir), r["line_number"], r["test_id"],
                f"{r['issue_text']} ({r['test_name']})", r["issue_severity"].lower(),
                confidence=r["issue_confidence"].lower(), cwe=(r.get("issue_cwe") or {}).get("id"))
        for r in data.get("results", [])
    ]
    annotate_bandit(findings, ctx.root)
    return engine_result("bandit", unit, findings)


# --------------------------------------------------------------------------- pip-audit
def summarize_advisory(text: str, limit: int = 220) -> str:
    """First useful sentence of an advisory (without markdown headers such as `### Impact`)."""
    text = re.sub(r"#+\s*(Impact|Summary|Description|Details|Overview|Vulnerability|Problem)\b:?", " ", text)
    summary = re.sub(r"\s+", " ", re.sub(r"[#*`]+", " ", text)).strip()
    return summary if len(summary) <= limit else summary[:limit].rsplit(" ", 1)[0] + "…"


async def pip_audit(unit: Unit, ctx: Context) -> dict[str, Any]:
    notes: list[str] = []
    skipped: list[str] = []
    with tempfile.TemporaryDirectory(prefix="code-audit-") as tmp:
        req = Path(tmp) / "requirements.txt"
        venv_python = find_venv_python(unit.dir)
        uv = require_bin("uv", "Install uv: https://docs.astral.sh/uv/", "CODE_AUDIT_UV")
        if venv_python:
            proc = await run([uv, "pip", "freeze", "--exclude-editable", "--python", str(venv_python)],
                             cwd=unit.dir, timeout=60)
            if proc.returncode != 0:
                raise tool_failure("uv pip freeze", proc)
            source = f"installed packages in {venv_python.parent.parent.name}/"
        elif (unit.dir / "uv.lock").exists():
            proc = await run([uv, "export", "--frozen", "--no-hashes", "--no-emit-project", "--quiet",
                              "--format", "requirements-txt"], cwd=unit.dir, timeout=60)
            if proc.returncode != 0:
                raise tool_failure("uv export", proc)
            source = "uv.lock"
        elif (unit.dir / "requirements.txt").exists():
            proc = None
            req = unit.dir / "requirements.txt"
            source = "requirements.txt"
        else:
            return engine_result("pip-audit", unit, skipped="no venv, uv.lock or requirements.txt")
        if proc is not None:
            pinned = []
            for line in proc.stdout.splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    (skipped if (" @ " in line or line.startswith("-")) else pinned).append(line)
            req.write_text("\n".join(pinned) + "\n", encoding="utf-8")
        args = ["-r", str(req), "-f", "json", "--progress-spinner", "off"]
        if proc is not None:
            args += ["--no-deps", "--disable-pip"]  # exact versions: no need to resolve
        audit = await run(uvx("pip-audit", *args), cwd=unit.dir)
    if audit.returncode not in (0, 1):
        raise tool_failure("pip-audit", audit)
    data = parse_json("pip-audit", audit)
    findings = []
    seen: set[tuple[str, str, str]] = set()
    source_file = None if source.startswith("installed packages") else (source if unit.rel == "." else f"{unit.rel}/{source}")
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            key = (dep["name"], str(dep.get("version")), v["id"])
            if key in seen:
                continue
            seen.add(key)
            fixes = v.get("fix_versions") or []
            findings.append(finding(
                source_file, None, v["id"],
                f"{dep['name']} {dep.get('version')}: {summarize_advisory(v.get('description') or '')}",
                "high", name=dep["name"], aliases=v.get("aliases"),
                fix=f"upgrade to {', '.join(fixes)}" if fixes else "no fixed version",
            ))
    notes.append(f"Source: {source}.")
    if skipped:
        notes.append("Not audited (direct/local references): " + ", ".join(skipped[:10]))
    return engine_result("pip-audit", unit, findings, notes)


# --------------------------------------------------------------------------- ruff
async def ruff(unit: Unit, ctx: Context) -> dict[str, Any]:
    proc = await run(uvx("ruff", "check", ".", "--output-format", "json", "--exit-zero", "--no-cache"), cwd=unit.dir)
    if proc.returncode != 0:
        raise tool_failure("ruff", proc)
    findings = [
        finding(ctx.rel(d["filename"], unit.dir), d["location"]["row"], d.get("code") or "syntax-error",
                d["message"], "medium" if not d.get("code") else "low", fixable=bool(d.get("fix")) or None)
        for d in parse_json("ruff", proc) or []
    ]
    return engine_result("ruff", unit, findings)

