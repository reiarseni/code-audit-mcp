"""Detection of the projects (units) inside the audited path.

Walks the root and up to two levels of subdirectories (skipping junk and git-ignored paths), so it finds
both single projects and `backend/` + `frontend/` monorepos or Laravel with React.
"""

from __future__ import annotations

import re
from pathlib import Path

from code_audit_mcp.core import JUNK_DIRS, TEST_DIR_NAMES, Unit, git_ignored, read_json

MAX_DEPTH = 2
PY_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile")
_REQUIREMENTS = re.compile(r"^requirements.*\.(txt|in)$")


def _python_label(directory: Path) -> str:
    text = ""
    for name in ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile"):
        file = directory / name
        if file.exists():
            text += file.read_text(encoding="utf-8", errors="replace").lower()
    for file in directory.glob("requirements*.txt"):
        text += file.read_text(encoding="utf-8", errors="replace").lower()
    for label, pattern in (("FastAPI", r"\bfastapi\b"), ("Flask", r"\bflask\b"), ("Django", r"\bdjango\b")):
        if re.search(pattern, text):
            return label
    return "Python"


def _php_label(composer: dict) -> str:
    require = {**composer.get("require", {}), **composer.get("require-dev", {})}
    if "laravel/framework" in composer.get("require", {}):
        return "Laravel"
    if any(p.startswith("illuminate/") for p in require) or "orchestra/testbench" in require:
        return "Laravel (package)"
    return "PHP"


def _node_label(directory: Path, package: dict) -> str:
    deps = {**package.get("dependencies", {}), **package.get("devDependencies", {})}
    if "next" in deps:
        return "Next.js"
    if "react" in deps:
        return "React"
    if "typescript" in deps or (directory / "tsconfig.json").exists():
        return "TypeScript"
    return "JavaScript"


def _dart_label(directory: Path) -> str:
    text = (directory / "pubspec.yaml").read_text(encoding="utf-8", errors="replace")
    return "Flutter" if re.search(r"^\s+sdk:\s*flutter\b", text, re.M) else "Dart"


def _is_python_project(directory: Path) -> bool:
    return any((directory / m).exists() for m in PY_MARKERS) or any(
        _REQUIREMENTS.match(f.name) for f in directory.iterdir() if f.is_file()
    )


def _units_in(directory: Path, root: Path) -> list[Unit]:
    rel = "." if directory == root else str(directory.relative_to(root))
    units: list[Unit] = []
    composer = read_json(directory / "composer.json") if (directory / "composer.json").exists() else None
    if isinstance(composer, dict):
        units.append(Unit("php", directory, _php_label(composer), rel))
    package = read_json(directory / "package.json") if (directory / "package.json").exists() else None
    if isinstance(package, dict) and (
        package.get("dependencies") or package.get("devDependencies") or (directory / "tsconfig.json").exists()
    ):
        units.append(Unit("node", directory, _node_label(directory, package), rel))
    if _is_python_project(directory):
        units.append(Unit("python", directory, _python_label(directory), rel))
    if (directory / "pubspec.yaml").exists():
        units.append(Unit("dart", directory, _dart_label(directory), rel))
    return units


def _subdirs(directory: Path) -> list[Path]:
    try:
        children = [c for c in directory.iterdir() if c.is_dir()]
    except OSError:
        return []
    ignored = git_ignored(directory, children)
    return sorted(
        c for c in children
        if not c.name.startswith(".") and c.name not in JUNK_DIRS and c.name not in TEST_DIR_NAMES
        and c.resolve() not in ignored and not c.name.endswith(".egg-info")
    )


def _has_workspaces(directory: Path) -> bool:
    package = read_json(directory / "package.json")
    return (isinstance(package, dict) and bool(package.get("workspaces"))) or (
        directory / "pnpm-workspace.yaml"
    ).exists()


def detect_units(root: Path) -> list[Unit]:
    found: list[Unit] = []
    frontier = [root]
    for depth in range(MAX_DEPTH + 1):
        next_frontier: list[Path] = []
        for directory in frontier:
            found.extend(_units_in(directory, root))
            if depth < MAX_DEPTH:
                next_frontier.extend(_subdirs(directory))
        frontier = next_frontier

    units: list[Unit] = []
    for unit in found:
        ancestors = [u for u in found if u.stack == unit.stack and u.dir != unit.dir and u.dir in unit.dir.parents]
        if not ancestors:
            units.append(unit)
        elif unit.stack == "node" and not any(_has_workspaces(a.dir) for a in ancestors):
            units.append(unit)  # e.g. tooling package.json at the root + a real frontend/
        # Nested Python/PHP/Dart (or Node workspaces) are covered by the outer unit.
    if not any(u.stack == "python" for u in units) and any(root.glob("*.py")):
        units.append(Unit("python", root, "Python", "."))
    return units
