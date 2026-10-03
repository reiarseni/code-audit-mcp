import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from code_audit_mcp.config import Config
from code_audit_mcp.core import AuditError, Context, Unit
from code_audit_mcp.engines import shared

FIXTURES = Path(__file__).parent / "fixtures" / "rules"


def test_complexity_severity() -> None:
    assert shared.complexity_severity(11) == ("C", "low")
    assert shared.complexity_severity(25) == ("D", "medium")
    assert shared.complexity_severity(41) == ("F", "high")


def test_parse_lizard_csv(tmp_path: Path) -> None:
    unit = Unit("node", tmp_path / "web", "React", "web")
    ctx = Context(tmp_path.resolve(), Config())
    csv_text = (
        '121,23,791,1,134,"syncItem@25-158@./src/sync.ts","./src/sync.ts","syncItem","syncItem ( x )",25,158\n'
        '7,1,38,1,7,"small@13-19@./src/a.ts","./src/a.ts","small","small ( )",13,19\n'
        '50,12,300,2,60,"Page@3-62@./src/page.tsx","./src/page.tsx","Page","Page ( p )",3,62\n'
    )
    findings = shared.parse_lizard_csv(csv_text, unit, ctx, threshold=11)
    assert [(f["file"], f["rule"], f["ccn"]) for f in findings] == [
        ("web/src/sync.ts", "complexity-D", 23), ("web/src/page.tsx", "complexity-C", 12)]


def test_registry_packs_by_stack() -> None:
    units = [Unit("python", Path("/a"), "FastAPI", "api"), Unit("php", Path("/b"), "Laravel", "."),
             Unit("node", Path("/c"), "React", "web")]
    assert shared.registry_packs(units) == ["p/secrets", "p/sql-injection", "p/python", "p/fastapi", "p/php",
                                            "p/typescript", "p/javascript", "p/react"]


def test_parse_semgrep_marks_own_rules(tmp_path: Path) -> None:
    ctx = Context(tmp_path.resolve(), Config())
    own = shared._own_prefix() + ".redis-keys-command"
    data = {"results": [
        {"check_id": own, "path": "app/x.py", "start": {"line": 3},
         "extra": {"message": "KEYS  blocks\n Redis", "severity": "WARNING", "metadata": {}}},
        {"check_id": "javascript.lang.security.audit.x", "path": "src/a.ts", "start": {"line": 9},
         "extra": {"message": "m", "severity": "ERROR", "metadata": {"cwe": ["CWE-79: XSS"]}}},
    ]}
    a, b = shared.parse_semgrep(data, ctx)
    assert (a["rule"], a["severity"], a["source"], a["message"]) == ("redis-keys-command", "medium", "own",
                                                                     "KEYS blocks Redis")
    assert (b["severity"], b["cwe"], b["source"]) == ("high", "CWE-79", "semgrep registry")


async def test_sensitive_files_tracked_and_not_ignored(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    tracked = [".env", ".env.example", ".env.testing", "backend/.env.production", "certs/server.pem",
               "data/app.sqlite3", "storage/app.log", "app/Backups.php", "database/schema.sql", "tests/fixtures/k.pem"]
    for name in [*tracked, "dump_2026.sql", "new.log", "ignored.key"]:
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text("X=1")
    (tmp_path / ".gitignore").write_text("ignored.key\n")
    subprocess.run(["git", "add", "-f", *tracked], cwd=tmp_path, check=True)
    result = await shared.sensitive_files([], Context(tmp_path.resolve(), Config()))
    found = {f["file"]: (f["rule"], f["severity"]) for f in result["findings"]}
    assert found[".env"] == ("env-file-in-git", "high")
    assert found[".env.testing"] == ("env-file-in-git", "low")
    assert found["backend/.env.production"] == ("env-file-in-git", "high")
    assert found["certs/server.pem"] == ("private-key-in-git", "high")
    assert found["data/app.sqlite3"] == ("data-dump-in-git", "medium")
    assert found["storage/app.log"] == ("log-file-in-git", "low")
    assert found["dump_2026.sql"] == ("data-dump-not-ignored", "low")
    for absent in (".env.example", "app/Backups.php", "database/schema.sql", "tests/fixtures/k.pem", "new.log",
                   "ignored.key"):
        assert absent not in found


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=Ana", "-c", "user.email=a@x", *args], cwd=cwd, check=True,
                   capture_output=True)


async def test_sensitive_files_by_content(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    files = {
        ".npmrc": "//registry.npmjs.org/:_authToken=npm_abc123\n",
        "web/.npmrc": "legacy-peer-deps=true\n",
        "auth.json": '{"github-oauth": {"github.com": "ghp_x"}}',
        "lang/en/auth.json": '{"failed": "Invalid credentials"}',
        "keys/AuthKey_ABC.p8": "-----BEGIN PRIVATE KEY-----",
        "app/android/key.properties": "storePassword=x\n",
    }
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    _git(tmp_path, "add", ".")
    result = await shared.sensitive_files([], Context(tmp_path.resolve(), Config()))
    found = {f["file"]: (f["rule"], f["severity"]) for f in result["findings"]}
    assert found == {
        ".npmrc": ("credentials-file-in-git", "high"),
        "auth.json": ("credentials-file-in-git", "high"),
        "keys/AuthKey_ABC.p8": ("private-key-in-git", "high"),
        "app/android/key.properties": ("credentials-file-in-git", "high"),
    }


async def test_sensitive_files_in_history(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    for name, text in {".env": "DB_PASSWORD=x", "app.py": "x = 1", "storage/app.log": "x",
                       "backend/.npmrc": "_authToken=abc", "web/.npmrc": "save-exact=true"}.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "initial")
    _git(tmp_path, "rm", "-q", "--cached", ".env", "storage/app.log", "backend/.npmrc", "web/.npmrc")
    (tmp_path / ".gitignore").write_text(".env\n*.log\n.npmrc\n")
    _git(tmp_path, "add", ".gitignore")
    _git(tmp_path, "commit", "-qm", "remove secrets")
    result = await shared.sensitive_files([], Context(tmp_path.resolve(), Config()))
    found = {f["file"]: f for f in result["findings"]}
    assert set(found) == {".env", "backend/.npmrc"}  # logs and token-less .npmrc do not count in history
    env = found[".env"]
    assert (env["rule"], env["severity"], env["author"]) == ("env-file-in-history", "high", "Ana")
    assert len(env["commit"]) >= 7 and "git filter-repo" in env["message"]

    # when auditing a subfolder, paths are relative to it
    result = await shared.sensitive_files([], Context((tmp_path / "backend").resolve(), Config()))
    assert [f["file"] for f in result["findings"]] == [".npmrc"]


def test_parse_gitleaks_groups_and_hides_secrets(tmp_path: Path) -> None:
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "conf.py").write_text('KEY = "sk_live_still_here"\n')

    def leak(rule: str, secret: str, file: str, commit: str, date: str) -> dict:
        return {"RuleID": rule, "Secret": secret, "Match": secret, "File": file, "Commit": commit, "Date": date,
                "StartLine": 3, "Author": "Ana", "Description": "Stripe token"}

    data = [
        leak("stripe-access-token", "sk_live_still_here", "api/conf.py", "bbbbbbbbbb", "2026-02-01T00:00:00Z"),
        leak("stripe-access-token", "sk_live_still_here", "api/conf.py", "aaaaaaaaaa", "2026-01-01T00:00:00Z"),
        leak("generic-api-key", "gone123", "api/old.py", "cccccccccc", "2026-03-01T00:00:00Z"),
        leak("generic-api-key", "fake", "api/tests/test_x.py", "dddddddddd", "2026-03-01T00:00:00Z"),
        leak("generic-api-key", "vend", "api/vendor/lib.php", "eeeeeeeeee", "2026-03-01T00:00:00Z"),
        leak("generic-api-key", "other", "web/x.ts", "ffffffffff", "2026-03-01T00:00:00Z"),
    ]
    findings = {f["file"]: f for f in shared.parse_gitleaks(data, "api/", tmp_path / "api")}
    assert set(findings) == {"conf.py", "old.py", "tests/test_x.py"}
    stripe = findings["conf.py"]
    assert (stripe["severity"], stripe["commit"], stripe["commits"]) == ("high", "aaaaaaaa", 2)
    assert "still in the code" in stripe["message"]
    assert findings["old.py"]["severity"] == "medium" and "history" in findings["old.py"]["message"]
    assert "likely_false_positive" in findings["tests/test_x.py"]
    assert "sk_live" not in json.dumps(list(findings.values()))


async def test_gitleaks_finds_deleted_secret(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    (tmp_path / "conf.py").write_text('stripe = "sk_live_51HabcdefGHIJKLmnopQRSTuvwx"\n')
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "a")
    _git(tmp_path, "rm", "-q", "conf.py")
    _git(tmp_path, "commit", "-qm", "b")
    try:
        result = await shared.gitleaks([], Context(tmp_path.resolve(), Config()))
    except AuditError as exc:
        pytest.skip(f"gitleaks not available: {exc}")
    [leak] = result["findings"]
    assert (leak["file"], leak["rule"], leak["author"]) == ("conf.py", "stripe-access-token", "Ana")
    assert "history" in leak["message"] and "sk_live" not in json.dumps(leak)


@pytest.mark.skipif(not shutil.which("uvx"), reason="requires uvx")
def test_own_semgrep_rules_detect_exactly_the_marked_lines(tmp_path: Path) -> None:
    # copy outside the repo: semgrep's default .semgrepignore excludes tests/
    target = tmp_path / "rules"
    shutil.copytree(FIXTURES, target)
    expected = set()
    for file in FIXTURES.rglob("*"):
        if file.is_file():
            for n, line in enumerate(file.read_text().splitlines(), 1):
                if m := re.search(r"BAD:([\w-]+)", line):
                    expected.add((file.relative_to(FIXTURES).as_posix(), n, m.group(1)))
    proc = subprocess.run(
        ["uvx", "-q", "semgrep", "scan", "--metrics=off", "--json", "--quiet", "--disable-version-check",
         "--config", str(shared.RULES_FILE), "."],
        cwd=target, capture_output=True, text=True, timeout=600,
    )
    data = json.loads(proc.stdout)
    assert not [e for e in data["errors"] if e.get("level") == "error"], data["errors"]
    found = {(r["path"], r["start"]["line"], r["check_id"].rsplit(".", 1)[-1]) for r in data["results"]}
    assert found == expected
