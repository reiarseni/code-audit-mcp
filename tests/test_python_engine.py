import shutil
from pathlib import Path

import pytest

from code_audit_mcp.config import Config
from code_audit_mcp.core import Context, Unit
from code_audit_mcp.engines import python


def _ctx(root: Path) -> Context:
    return Context(root.resolve(), Config())


def test_parse_vulture_extracts_fields(tmp_path: Path) -> None:
    out = (
        f"{tmp_path}/pkg/mod.py:12: unused function 'helper' (60% confidence)\n"
        "pkg/mod.py:3: unused import 'os' (90% confidence)\n"
        "pkg/mod.py:40: unreachable code after 'return' (100% confidence, 2 lines)\n"
        "garbage that does not fit\n"
    )
    findings = python.parse_vulture(out, tmp_path, _ctx(tmp_path))
    assert [(f["file"], f["line"], f["rule"], f.get("name")) for f in findings] == [
        ("pkg/mod.py", 12, "unused-function", "helper"),
        ("pkg/mod.py", 3, "unused-import", "os"),
        ("pkg/mod.py", 40, "unreachable-code-after", "return"),
    ]


def test_source_index_decorators_and_model_fields() -> None:
    src = (
        "@router.get(\n    '/x',\n)\nasync def endpoint():\n    pass\n\n"
        "class UserOut(BaseModel):\n    email: str\n    model_config = {}\n\n"
        "class Plain:\n    x = 1\n\n"
        "@dataclass\nclass P:\n    y: int = 0\n"
    )
    decorators, fields = python.source_index(src)
    assert decorators[1] == ["router.get"] and decorators[4] == ["router.get"]
    assert {8, 9, 16} <= fields and 12 not in fields


def test_annotate_false_positives(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "@app.post('/x')\ndef create():\n    pass\n\ndef orphan():\n    pass\n\n"
        "class Out(BaseModel):\n    issuer: str\n"
    )
    (tmp_path / "alembic" / "versions").mkdir(parents=True)
    (tmp_path / "alembic" / "versions" / "0001.py").write_text("revision = '1'\n")
    findings = [
        {"file": "app.py", "line": 1, "rule": "unused-function", "name": "create"},
        {"file": "app.py", "line": 5, "rule": "unused-function", "name": "orphan"},
        {"file": "app.py", "line": 9, "rule": "unused-variable", "name": "issuer"},
        {"file": "alembic/versions/0001.py", "line": 1, "rule": "unused-variable", "name": "revision"},
        {"file": "app.py", "line": 30, "rule": "unused-method", "name": "on_mount"},
    ]
    python.annotate_false_positives(findings, tmp_path)
    assert findings[0]["likely_false_positive"] == "registered by decorator @app.post"
    assert "likely_false_positive" not in findings[1]
    assert "model" in findings[2]["likely_false_positive"]
    assert "Alembic" in findings[3]["likely_false_positive"]
    assert "framework" in findings[4]["likely_false_positive"]


def test_group_deptry_collapses_by_module_and_prefixes_unit() -> None:
    raw = [
        {"error": {"code": "DEP001", "message": "x"}, "module": "yaml", "location": {"file": "a.py", "line": 1}},
        {"error": {"code": "DEP001", "message": "x"}, "module": "yaml", "location": {"file": "b.py", "line": 7}},
        {"error": {"code": "DEP002", "message": "x"}, "module": "ruff", "location": {"file": "pyproject.toml"}},
    ]
    out = python.group_deptry(raw, "backend")
    assert out[0]["rule"] == "missing-dependency" and out[0]["occurrences"] == 2
    assert (out[0]["file"], out[0]["line"]) == ("backend/a.py", 1)
    assert out[1] | {} == out[1] and out[1]["file"] == "backend/pyproject.toml" and out[1]["rule"] == "unused-dependency"


def test_dev_groups_only_dev_like_names() -> None:
    assert python.dev_groups({"project": {"optional-dependencies": {"dev": [], "gemini": [], "Tests": []}}}) == [
        "dev", "Tests"]


def test_summarize_advisory_drops_markdown_headers() -> None:
    text = "### Impact\nServices using **IDN** names are vulnerable.\n\n### Patches\nUpgrade."
    assert python.summarize_advisory(text).startswith("Services using IDN names are vulnerable.")
    assert len(python.summarize_advisory("word " * 100)) <= 221


@pytest.mark.skipif(not shutil.which("uvx"), reason="requires uvx")
async def test_vulture_end_to_end_tests_count_as_usage(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "mod.py").write_text(
        "import os\n\nREGISTRY = {}\n\n"
        "def register(fn):\n    REGISTRY[fn.__name__] = fn\n    return fn\n\n"
        "@register\ndef plugin():\n    return 1\n\n"
        "def orphan():\n    return 2\n\ndef only_tests():\n    return 3\n"
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_mod.py").write_text("from pkg.mod import only_tests\n\ndef test_x():\n    only_tests()\n")
    unit = Unit("python", tmp_path.resolve(), "Python", ".")
    result = await python.vulture(unit, _ctx(tmp_path))
    by_name = {f["name"]: f for f in result["findings"]}
    assert by_name["os"]["rule"] == "unused-import"
    assert "likely_false_positive" not in by_name["orphan"]
    assert by_name["plugin"]["likely_false_positive"] == "registered by decorator @register"
    assert "only_tests" not in by_name and "test_x" not in by_name


@pytest.mark.parametrize("value, secret", [
    ("HEAD", False), ("refresh_token:", False), ("password", False), ("refs/heads/main", False),
    ("MY_SECRET_KEY", False), ("s3cr3t-Pa55w0rd!", True), ("hunter2xyz9", True),
])
def test_looks_like_secret(value: str, secret: bool) -> None:
    assert python.looks_like_secret(value) is secret


def test_annotate_bandit(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text(
        "import subprocess\n"
        "subprocess.run(['git', 'status'], check=True)\n"
        "subprocess.run(['git', *args])\n"
        "subprocess.run(\n    ['ls', '-l'],\n)\n"
    )
    findings = [
        {"file": "m.py", "line": 1, "rule": "B404", "message": "x"},
        {"file": "m.py", "line": 2, "rule": "B603", "message": "x"},
        {"file": "m.py", "line": 3, "rule": "B603", "message": "x"},
        {"file": "m.py", "line": 5, "rule": "B607", "message": "x"},
        {"file": "m.py", "line": 9, "rule": "B105", "message": "Possible hardcoded password: 'HEAD' (x)"},
        {"file": "m.py", "line": 9, "rule": "B105", "message": "Possible hardcoded password: 'Xk9#mQ2!pL' (x)"},
    ]
    python.annotate_bandit(findings, tmp_path)
    marked = ["likely_false_positive" in f for f in findings]
    assert marked == [True, True, False, True, True, False]
