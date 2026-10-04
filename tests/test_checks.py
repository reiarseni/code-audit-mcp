import shutil
from pathlib import Path

import pytest

from code_audit_mcp import checks
from code_audit_mcp.config import Config
from code_audit_mcp.core import AuditError, Context


def test_every_check_has_engines() -> None:
    for name in checks.CHECKS:
        assert checks.UNIT_ENGINES.get(name) or checks.ROOT_ENGINES.get(name)
    for engines in checks.UNIT_ENGINES.values():
        for engine_list in engines.values():
            assert all(e in checks.ENGINE_NAMES for e in engine_list)


def test_postprocess_filters_sorts_and_truncates(tmp_path: Path) -> None:
    ctx = Context(tmp_path, Config(ignore=["B404"], exclude=["legacy/**"]))
    result = {"engine": "x", "unit": "u", "findings": [
        {"file": "a.py", "line": 9, "rule": "R1", "severity": "low", "message": "m9"},
        {"file": "a.py", "line": 1, "rule": "R2", "severity": "high", "likely_false_positive": "x"},
        {"file": "b.py", "line": 2, "rule": "R3", "severity": "critical", "message": "m2"},
        {"file": "c.py", "line": 2, "rule": "B404", "severity": "low"},
        {"file": "legacy/d.py", "line": 2, "rule": "R4", "severity": "high"},
        {"file": "a.py", "line": 3, "rule": "R1", "severity": "medium", "message": "m3"},
    ]}
    out = checks._postprocess(result, ctx, checks.Page(limit=2, false_positives=False))
    assert out["count"] == 4 and out["likely_false_positives"] == 1 and out["truncated"] == 1
    assert [f["rule"] for f in out["findings"]] == ["R3", "R1"]
    assert out["by_rule"] == {"R1": 2, "R3": 1}


def test_postprocess_severity_file_offset_and_shared_messages(tmp_path: Path) -> None:
    ctx = Context(tmp_path, Config())

    def result() -> dict:
        return {"engine": "semgrep", "unit": "u", "findings": [
            {"file": "app/Http/A.php", "line": 1, "rule": "xss", "severity": "high", "message": "Long XSS"},
            {"file": "app/Http/B.php", "line": 2, "rule": "xss", "severity": "high", "message": "Long XSS"},
            {"file": "app/Models/C.php", "line": 3, "rule": "sql", "severity": "medium", "message": "SQL"},
            {"file": "app/Http/D.php", "line": 4, "rule": "env", "severity": "low", "message": "env"},
        ]}

    out = checks._postprocess(result(), ctx, checks.Page(limit=10, min_severity="medium", file="app/Http/**"))
    assert [f["file"] for f in out["findings"]] == ["app/Http/A.php", "app/Http/B.php"]
    assert out["rules"] == {"xss": "Long XSS"} and all("message" not in f for f in out["findings"])
    out = checks._postprocess(result(), ctx, checks.Page(limit=2, offset=2, file="app/Http"))
    assert [f["file"] for f in out["findings"]] == ["app/Http/D.php"] and "truncated" not in out
    assert out["findings"][0]["message"] == "env" and "rules" not in out


async def test_engine_errors_do_not_break_the_check(tmp_path: Path) -> None:
    async def boom() -> dict:
        raise ValueError("broken")

    out = await checks._guarded("engine", None, boom())
    assert out == {"engine": "engine", "unit": "whole project", "error": "ValueError: broken"}


async def test_unknown_check_and_empty_project(tmp_path: Path) -> None:
    with pytest.raises(AuditError):
        await checks.run_check("nope", str(tmp_path))
    with pytest.raises(AuditError, match="project detected"):
        await checks.run_check("lint", str(tmp_path))


@pytest.mark.skipif(not shutil.which("uvx"), reason="requires uvx")
async def test_run_check_and_audit_on_python_project(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import os\n\ndef used():\n    return 1\n\nprint(used())\n")
    (tmp_path / ".code-audit.toml").write_text('[security]\nregistry = false\n')
    result = await checks.run_check("dead_code", str(tmp_path))
    assert result["stacks"] == ["Python (.)"] and result["total"] == 1
    assert result["results"][0]["findings"][0]["name"] == "os"
    report = await checks.run_audit(str(tmp_path))
    assert set(report["checks"]) == set(checks.CHECKS)
    assert report["summary"]["dead_code"]["total"] == 1
    assert report["checks"]["dead_code"][0]["top"][0]["rule"] == "unused-import"


async def test_server_returns_compact_text_without_structured_copy(tmp_path: Path) -> None:
    from mcp.shared.memory import create_connected_server_and_client_session

    from code_audit_mcp.server import mcp

    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert tools["check"].outputSchema is None and tools["check"].annotations.readOnlyHint
        result = await client.call_tool("check", {"name": "lint", "path": str(tmp_path)})
    assert result.structuredContent is None and len(result.content) == 1
    assert "project detected" in result.content[0].text


def test_brief_keeps_shared_messages_of_its_top(tmp_path: Path) -> None:
    ctx = Context(tmp_path, Config())
    findings = [{"file": f"f{i}.py", "line": i, "rule": "dup", "severity": "high", "message": "same"} for i in range(7)]
    findings.append({"file": "z.py", "line": 1, "rule": "alone", "severity": "low", "message": "unique"})
    brief = checks._brief(checks._postprocess({"engine": "e", "unit": "u", "findings": findings}, ctx, checks.Page()))
    assert brief["rules"] == {"dup": "same"} and len(brief["top"]) == 5
    assert brief["by_rule"] == {"dup": 7, "alone": 1}
