"""Engines shared by all stacks: complexity (lizard), security (semgrep with own rules
for Postgres, Redis, Laravel, FastAPI/Flask, React and Flutter) and sensitive files in
git (tracked, not ignored or in history)."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import re
import subprocess
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from code_audit_mcp.core import (
    JUNK_DIRS,
    AuditError,
    Context,
    Unit,
    engine_result,
    ensure_release_binary,
    finding,
    git_tracked,
    is_test_path,
    lizard_excludes,
    parse_json,
    run,
    tool_failure,
    uvx,
    which,
)

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "stack.yml"

LIZARD_LANGUAGES = {
    "python": ["python"],
    "php": ["php"],
    "node": ["typescript", "tsx", "javascript"],
}


def complexity_severity(ccn: int) -> tuple[str, str]:
    """(radon-style rank, severity)."""
    for limit, rank, severity in ((5, "A", "info"), (10, "B", "info"), (20, "C", "low"), (30, "D", "medium"),
                                  (40, "E", "high")):
        if ccn <= limit:
            return rank, severity
    return "F", "high"


def parse_lizard_csv(text: str, unit: Unit, ctx: Context, threshold: int) -> list[dict[str, Any]]:
    findings = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 11 or not row[1].isdigit():
            continue
        nloc, ccn, file, function, start = int(row[0]), int(row[1]), row[6], row[7], int(row[9])
        if ccn < threshold:
            continue
        rank, severity = complexity_severity(ccn)
        findings.append(finding(ctx.rel(file, unit.dir), start, f"complexity-{rank}",
                                f"{function}: cyclomatic complexity {ccn} in {nloc} lines", severity,
                                name=function, ccn=ccn))
    return sorted(findings, key=lambda f: -f["ccn"])


async def lizard(unit: Unit, ctx: Context) -> dict[str, Any]:
    args = [".", "--csv"]
    for lang in LIZARD_LANGUAGES[unit.stack]:
        args += ["-l", lang]
    for pattern in lizard_excludes(unit.dir):
        args += ["-x", pattern]
    proc = await run(uvx("lizard", *args), cwd=unit.dir)
    if proc.returncode not in (0, 1):
        raise tool_failure("lizard", proc)
    threshold = ctx.config.complexity_threshold
    findings = [f for f in parse_lizard_csv(proc.stdout, unit, ctx, threshold) if not is_test_path(f["file"])]
    return engine_result("lizard", unit, findings,
                         [f"Threshold: complexity ≥ {threshold}. Ranks: C 11-20, D 21-30, E 31-40, F 41+."])


# --------------------------------------------------------------------------- semgrep
SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
SEMGREP_EXCLUDES = sorted(JUNK_DIRS | {"public/build", "bootstrap/cache", "*.min.js", "*.map"})


def registry_packs(units: list[Unit]) -> list[str]:
    packs = ["p/secrets", "p/sql-injection"]
    for unit in units:
        if unit.stack == "python":
            packs.append("p/python")
            if unit.label in ("FastAPI", "Flask"):
                packs.append(f"p/{unit.label.lower()}")
        elif unit.stack == "php":
            packs.append("p/php")
        elif unit.stack == "node":
            packs += ["p/typescript", "p/javascript"]
            if unit.label in ("React", "Next.js"):
                packs.append("p/react")
    return list(dict.fromkeys(packs))


def parse_semgrep(data: dict[str, Any], ctx: Context) -> list[dict[str, Any]]:
    findings = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {}) or {}
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        rule = r["check_id"].rsplit(".", 1)[-1]
        message = re.sub(r"\s+", " ", r["extra"].get("message", "")).strip()
        findings.append(finding(
            ctx.rel(r["path"]), r["start"]["line"], rule, message[:400],
            SEMGREP_SEVERITY.get(r["extra"].get("severity", ""), "medium"),
            cwe=str(cwe).split(":")[0] if cwe else None,
            source="own" if r["check_id"].startswith(_own_prefix()) else "semgrep registry",
        ))
    return findings


def _own_prefix() -> str:
    # semgrep prefixes the id of local rules with the file path in dot notation
    return str(RULES_FILE.parent).strip("/").replace("/", ".")


async def semgrep(units: list[Unit], ctx: Context) -> dict[str, Any]:
    configs = ["--config", str(RULES_FILE)]
    notes = ["Own rules: interpolated SQL (Postgres), KEYS/FLUSHALL (Redis), Laravel, FastAPI/Flask, React, "
             "Flutter/Android/iOS."]
    packs = registry_packs(units) if ctx.config.registry else []
    for pack in packs:
        configs += ["--config", pack]
    base = ["scan", "--metrics=off", "--json", "--quiet", "--disable-version-check"]
    for pattern in SEMGREP_EXCLUDES:
        base += ["--exclude", pattern]
    proc = await run(uvx("semgrep", *base, *configs, "."), cwd=ctx.root)
    if packs and (proc.returncode not in (0, 1) or not proc.stdout.lstrip().startswith("{")):
        notes.append("Could not download the registry packs (offline?); own rules only.")
        proc = await run(uvx("semgrep", *base, "--config", str(RULES_FILE), "."), cwd=ctx.root)
    elif packs:
        notes.append("Registry packs: " + ", ".join(packs) + ".")
    if proc.returncode not in (0, 1):
        raise tool_failure("semgrep", proc)
    data = parse_json("semgrep", proc)
    findings = [f for f in parse_semgrep(data, ctx) if not is_test_path(f["file"])]
    errors = [e for e in data.get("errors", []) if e.get("level") == "error"]
    if errors:
        notes.append(f"semgrep could not analyze {len(errors)} file(s) (syntax errors or timeout).")
    return engine_result("semgrep", None, findings, notes)


# --------------------------------------------------------------------------- sensitive files
_ENV_TEMPLATES = (".example", ".sample", ".dist", ".template", ".defaults")
# (pattern on the path, rule, severity, what it contains)
SENSITIVE_PATTERNS = [
    (re.compile(r"(^|/)\.env(\.[\w.-]+)?$"), "env-file", "high", "environment variables (DB, Redis, APP_KEY…)"),
    (re.compile(r"\.(pem|key|p8|p12|pfx|jks|keystore|kdbx|ppk)$|(^|/)id_(rsa|dsa|ecdsa|ed25519)$", re.I),
     "private-key", "high", "private keys or certificates"),
    (re.compile(r"(^|/)(\.pypirc|\.netrc|\.pgpass|\.git-credentials|\.htpasswd|key\.properties)$"),
     "credentials-file", "high", "credentials (package registries, DB, git or the Android keystore)"),
    (re.compile(r"\.(sqlite3?|db)$|\.sql\.(gz|zip|bz2)$|(^|/)[^/]*dump[^/]*\.sql$|\.(bak|dump)$", re.I),
     "data-dump", "medium", "real data or database dumps"),
]
# Files that many projects commit without secrets: they only count if their content carries credentials.
CONTENT_PATTERNS = [
    (re.compile(r"(^|/)(\.npmrc|\.yarnrc\.yml)$"), re.compile(r"_auth(Token)?\s*=|_password\s*=|npmAuthToken\s*:"),
     "credentials-file", "high", "npm registry tokens"),
    (re.compile(r"(^|/)auth\.json$"),
     re.compile(r'"(http-basic|github-oauth|gitlab-token|gitlab-oauth|bitbucket-oauth|bearer)"'),
     "credentials-file", "high", "Composer credentials for private repositories"),
]
LOG_FILE = re.compile(r"\.log$", re.I)
_LOW_VALUE_IN_HISTORY = {"log-file"}


def sensitive_kind(path: str, versioned: bool, read: Callable[[], str | None]) -> tuple[str, str, str] | None:
    """(rule, severity, what it contains) if `path` is a sensitive file; `read` returns its content if needed."""
    if path.endswith(_ENV_TEMPLATES) or is_test_path(path):
        return None
    for pattern, rule, severity, content in SENSITIVE_PATTERNS:
        if pattern.search(path):
            if rule == "env-file" and path.endswith((".testing", ".test", ".ci")):
                severity = "low"
            return rule, severity, content
    for pattern, secret, rule, severity, content in CONTENT_PATTERNS:
        if pattern.search(path):
            text = read()
            return (rule, severity, content) if text and secret.search(text) else None
    if versioned and LOG_FILE.search(path):
        return "log-file", "low", "logs that may contain personal data or tokens"
    return None


def classify_sensitive(path: str, tracked: bool, root: Path | None = None) -> dict[str, Any] | None:
    def read() -> str | None:
        try:
            return (root / path).read_text(encoding="utf-8", errors="replace") if root else None
        except OSError:
            return None

    kind = sensitive_kind(path, tracked, read)
    if kind is None:
        return None
    rule, severity, content = kind
    if tracked:
        message = (f"{path} is tracked in git: {content} stay in the history; remove it from the repo, "
                   "add it to .gitignore and rotate whatever it contains")
    else:
        message = f"{path} is not ignored by .gitignore: a `git add .` would stage it ({content})"
        severity = {"high": "medium", "medium": "low"}.get(severity, severity)
    return finding(path, None, f"{rule}-{'in-git' if tracked else 'not-ignored'}", message, severity)


HISTORY_REFS = ["--branches", "--tags", "--remotes"]  # without refs/stash: stashes are not published


def parse_added_history(text: str) -> dict[str, tuple[str, str, str]]:
    """{path: (commit, author, date)} of the oldest commit that added each path (`git log` goes newest to oldest)."""
    added: dict[str, tuple[str, str, str]] = {}
    for block in text.split("\x1e"):
        lines = block.strip("\n").split("\n")
        header = lines[0].split("\x1f")
        if len(header) != 3:
            continue
        for path in lines[1:]:
            if path:
                added[path] = (header[0], header[1], header[2])
    return added


async def _history_findings(ctx: Context, current: set[str]) -> list[dict[str, Any]]:
    git = which("git")
    if not git:
        return []
    proc = await run([git, "-c", "core.quotePath=false", "log", *HISTORY_REFS, "--diff-filter=A", "--name-only",
                      "--relative", "--format=%x1e%h%x1f%an%x1f%as"], cwd=ctx.root, timeout=180)
    if proc.returncode != 0:
        return []  # repo without commits
    findings = []
    for path, (commit, author, date) in parse_added_history(proc.stdout).items():
        if path in current:
            continue  # already reported as tracked
        def read(commit: str = commit, path: str = path) -> str | None:
            shown = subprocess.run([git, "show", f"{commit}:./{path}"], cwd=ctx.root, capture_output=True,
                                   text=True, timeout=20)
            return shown.stdout if shown.returncode == 0 else None

        kind = sensitive_kind(path, True, read)
        if kind is None or kind[0] in _LOW_VALUE_IN_HISTORY:
            continue
        rule, severity, content = kind
        findings.append(finding(
            path, None, f"{rule}-in-history",
            f"{path} is no longer tracked, but it was added in commit {commit} ({author}, {date}) and is still in the "
            f"history: {content}. Rotate whatever it contained; removing it from history requires rewriting it "
            "(git filter-repo) and force-pushing", severity, commit=commit, author=author, date=date,
        ))
    return findings


async def sensitive_files(units: list[Unit], ctx: Context) -> dict[str, Any]:
    tracked = git_tracked(ctx.root)
    if tracked is None:
        return engine_result("git", None, skipped="not a git repository")
    untracked = git_tracked(ctx.root, untracked=True) or []
    findings = [f for path, is_tracked in [(p, True) for p in tracked] + [(p, False) for p in untracked]
                if (f := classify_sensitive(path, is_tracked, ctx.root))]
    findings += await _history_findings(ctx, set(tracked))
    return engine_result("git", None, findings,
                         ["Includes files that were added in history (branches, tags and remotes) and later "
                          "deleted."])


# --------------------------------------------------------------------------- secrets in history
GITLEAKS_VERSION = "8.30.1"
_GITLEAKS_RELEASE = "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}"
GITLEAKS_URL = _GITLEAKS_RELEASE + "_{os}_{arch}.tar.gz"
GITLEAKS_CHECKSUMS = _GITLEAKS_RELEASE + "_checksums.txt"
GENERIC_SECRET_RULES = {"generic-api-key"}


def parse_gitleaks(data: list[dict[str, Any]], prefix: str, root: Path) -> list[dict[str, Any]]:
    """One finding per secret (rule + value), with the oldest commit it appears in.

    The secret value never leaves here: it is only used to group and to tell whether it is still in the code.
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in data:
        file = item.get("File", "")
        if not file.startswith(prefix) or any(part in JUNK_DIRS for part in Path(file).parts[:-1]):
            continue
        groups.setdefault((item["RuleID"], item.get("Secret", "")), []).append({**item, "File": file[len(prefix):]})
    findings = []
    for (rule, secret), items in groups.items():
        first = min(items, key=lambda i: i.get("Date", ""))
        files = sorted({i["File"] for i in items})
        present = [f for f in files if secret and _file_contains(root / f, secret)]
        where = (f"still in the code ({', '.join(present)})" if present
                 else "no longer in the code, but still in git history")
        item = finding(
            first["File"], first.get("StartLine"), rule,
            f"{first.get('Description', 'Secret')} — {where}. Revoke it and generate a new one: removing it from the code "
            "is not enough", "medium" if rule in GENERIC_SECRET_RULES else "high",
            commit=first.get("Commit", "")[:8], author=first.get("Author"), date=first.get("Date", "")[:10],
            commits=len({i.get("Commit") for i in items}), files=files if len(files) > 1 else None,
        )
        if all(is_test_path(f) for f in files):
            item["likely_false_positive"] = "only appears in tests: usually a test value"
        findings.append(item)
    return findings


def _file_contains(path: Path, text: str) -> bool:
    try:
        return text in path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


async def gitleaks(units: list[Unit], ctx: Context) -> dict[str, Any]:
    git = which("git")
    prefix_proc = await run([git, "rev-parse", "--show-prefix"], cwd=ctx.root, timeout=20) if git else None
    if prefix_proc is None or prefix_proc.returncode != 0:
        return engine_result("gitleaks", None, skipped="not a git repository")
    binary = which("gitleaks", "CODE_AUDIT_GITLEAKS") or str(await ensure_release_binary(
        "gitleaks", GITLEAKS_VERSION, GITLEAKS_URL, GITLEAKS_CHECKSUMS))
    proc = await run([binary, "git", "--log-opts=" + " ".join(HISTORY_REFS), "--no-banner", "--exit-code", "0",
                      "--report-format", "json", "--report-path", "-", "."], cwd=ctx.root)
    if proc.returncode != 0:
        raise tool_failure("gitleaks", proc)
    data = parse_json("gitleaks", proc, proc.stdout[proc.stdout.find("["):])
    findings = parse_gitleaks(data, prefix_proc.stdout.strip(), ctx.root)
    return engine_result("gitleaks", None, findings,
                         ["Full history of branches, tags and remotes. Secrets are not shown."])


# --------------------------------------------------------------------------- CVEs via OSV.dev
OSV_API = "https://api.osv.dev/v1"
OSV_BATCH = 1000
OSV_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _osv_request(path: str, payload: Any = None) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(OSV_API + path, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as resp:  # nosec B310: OSV_API is a fixed https URL
        return json.load(resp)


async def osv_query(ecosystem: str, packages: list[tuple[str, str]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """{(package, version): [full OSV vulnerabilities]} for the exact versions in a lockfile."""
    packages = sorted(set(packages))
    ids: dict[tuple[str, str], list[str]] = {}
    try:
        for i in range(0, len(packages), OSV_BATCH):
            chunk = packages[i:i + OSV_BATCH]
            queries = [{"package": {"name": name, "ecosystem": ecosystem}, "version": version} for name, version in chunk]
            data = await asyncio.to_thread(_osv_request, "/querybatch", {"queries": queries})
            for package, result in zip(chunk, data.get("results", []), strict=False):
                if result.get("vulns"):
                    ids[package] = [v["id"] for v in result["vulns"]]
        unique = sorted({i for found in ids.values() for i in found})
        details = dict(zip(unique, await asyncio.gather(
            *(asyncio.to_thread(_osv_request, f"/vulns/{i}") for i in unique)), strict=True))
    except (OSError, ValueError) as exc:
        raise AuditError(f"Could not query OSV.dev (offline?): {exc}") from exc
    return {package: [details[i] for i in found] for package, found in ids.items()}


def osv_findings(results: dict[tuple[str, str], list[dict[str, Any]]], ecosystem: str, lock_rel: str,
                 direct: set[str] | None = None) -> list[dict[str, Any]]:
    findings = []
    for (name, version), vulns in sorted(results.items()):
        seen: set[str] = set()
        for v in vulns:
            if v["id"] in seen:
                continue  # the same advisory under another id (GHSA and CVE)
            seen.update([v["id"], *v.get("aliases", [])])
            fixed = sorted({event["fixed"] for affected in v.get("affected", [])
                            if affected.get("package", {}).get("name") == name
                            and affected.get("package", {}).get("ecosystem") == ecosystem
                            for r in affected.get("ranges", []) for event in r.get("events", []) if "fixed" in event})
            severity = str((v.get("database_specific") or {}).get("severity", "")).upper()
            summary = v.get("summary") or (v.get("details") or "").strip().split("\n")[0][:200]
            findings.append(finding(
                lock_rel, None, v["id"], f"{name} {version}: {summary}", OSV_SEVERITY.get(severity, "high"),
                name=name, aliases=v.get("aliases"), direct=bool(direct and name in direct) or None,
                fix=f"upgrade to {', '.join(fixed)}" if fixed else "no fixed version",
            ))
    return findings
