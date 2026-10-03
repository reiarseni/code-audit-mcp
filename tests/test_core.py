import json
import subprocess
from pathlib import Path

import pytest

from code_audit_mcp.config import Config, load_config
from code_audit_mcp.core import AuditError, Context, is_test_path, load_jsonc, resolve_root
from code_audit_mcp.detect import detect_units


def test_load_jsonc_strips_comments_and_trailing_commas_but_not_urls() -> None:
    text = '{\n  // comment\n  "$schema": "https://x.dev/s.json", /* block */\n  "paths": {"@/*": ["./src/*"],},\n}'
    assert load_jsonc(text) == {"$schema": "https://x.dev/s.json", "paths": {"@/*": ["./src/*"]}}


@pytest.mark.parametrize("path, expected", [
    ("tests/Feature/UserTest.php", True),
    ("app/Http/Controllers/UserController.php", False),
    ("src/components/Button.test.tsx", True),
    ("e2e/login.spec.ts", True),
    ("backend/tests/test_api.py", True),
    ("backend/app/conftest.py", True),
    ("src/app/testimonials.py", False),
])
def test_is_test_path(path: str, expected: bool) -> None:
    assert is_test_path(path) is expected


def test_config_ignore_rules_names_and_paths(tmp_path: Path) -> None:
    (tmp_path / ".code-audit.toml").write_text(
        'exclude = ["legacy/**"]\nignore = ["B404", "DEP002:ruff", "unused-method:*::form"]\n'
        '[dead_code]\nignore_names = ["on_*"]\n[complexity]\nthreshold = 15\n[security]\nregistry = false\n'
    )
    config = load_config(tmp_path)
    assert config.complexity_threshold == 15 and config.registry is False
    assert config.is_ignored({"file": "legacy/old.py", "rule": "x"})
    assert config.is_ignored({"file": "a.py", "rule": "B404"})
    assert config.is_ignored({"rule": "DEP002", "name": "ruff"})
    assert not config.is_ignored({"rule": "DEP002", "name": "httpx"})
    assert config.is_ignored({"rule": "unused-method", "name": "App\\Filament\\UserResource::form"})
    assert config.is_ignored({"rule": "unused-method", "name": "on_click"})
    assert not config.is_ignored({"file": "app/x.py", "rule": "unused-method", "name": "handle_click"})


def test_config_with_syntax_error_warns_instead_of_failing(tmp_path: Path) -> None:
    (tmp_path / ".code-audit.toml").write_text("ignore = [")
    config = load_config(tmp_path)
    assert config.warnings and config.ignore == []


def test_context_rel(tmp_path: Path) -> None:
    ctx = Context(tmp_path.resolve(), Config())
    assert ctx.rel("x.py", tmp_path / "backend") == "backend/x.py"
    assert ctx.rel(tmp_path / "a" / "b.ts") == "a/b.ts"


def test_resolve_root_rejects_missing_path(tmp_path: Path) -> None:
    with pytest.raises(AuditError):
        resolve_root(str(tmp_path / "nope"))


def _write(path: Path, content: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if isinstance(content, str) else json.dumps(content))


def test_detect_monorepo_laravel_react_and_fastapi(tmp_path: Path) -> None:
    _write(tmp_path / "api" / "composer.json", {"require": {"laravel/framework": "^12.0"}})
    _write(tmp_path / "api" / "package.json", {"devDependencies": {"vite": "^6"}})
    _write(tmp_path / "web" / "package.json", {"dependencies": {"react": "^18"}})
    _write(tmp_path / "services" / "ml" / "requirements.txt", "fastapi==0.115\nuvicorn\n")
    _write(tmp_path / "web" / "node_modules" / "x" / "package.json", {"dependencies": {"y": "1"}})
    _write(tmp_path / "legacy" / "pyproject.toml", "[project]\nname='x'\ndependencies=['flask']\n")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text("/legacy/\n")
    names = sorted(u.name for u in detect_units(tmp_path))
    assert names == ["FastAPI (services/ml)", "JavaScript (api)", "Laravel (api)", "React (web)"]


def test_detect_skips_nested_units_of_same_stack_under_workspaces(tmp_path: Path) -> None:
    _write(tmp_path / "package.json", {"workspaces": ["packages/*"], "devDependencies": {"typescript": "5"}})
    _write(tmp_path / "packages" / "ui" / "package.json", {"dependencies": {"react": "^18"}})
    assert [u.name for u in detect_units(tmp_path)] == ["TypeScript (.)"]


def test_detect_plain_scripts_and_laravel_package(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text("print(1)\n")
    _write(tmp_path / "pkg" / "composer.json", {"require": {"illuminate/support": "^11.0"}})
    assert sorted(u.name for u in detect_units(tmp_path)) == ["Laravel (package) (pkg)", "Python (.)"]


def test_detect_flutter_app_and_dart_package(tmp_path: Path) -> None:
    _write(tmp_path / "mobile" / "pubspec.yaml", "name: app\ndependencies:\n  flutter:\n    sdk: flutter\n")
    _write(tmp_path / "mobile" / "packages" / "core" / "pubspec.yaml", "name: core\n")
    _write(tmp_path / "cli" / "pubspec.yaml", "name: cli\ndependencies:\n  args: ^2.0.0\n")
    assert sorted(u.name for u in detect_units(tmp_path)) == ["Dart (cli)", "Flutter (mobile)"]
