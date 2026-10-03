"""Shared pieces: process execution, tool cache, paths, git and finding format.

Invariant principle: nothing is ever written to the audited project. Tools run through
uvx/npx or from `~/.cache/code-audit-mcp`; the project is only read.
"""

from __future__ import annotations

import asyncio
import fcntl
import fnmatch
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import urllib.request
import weakref
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from code_audit_mcp.config import Config

TIMEOUT_S = float(os.environ.get("CODE_AUDIT_TIMEOUT", "900"))
_JOBS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = weakref.WeakKeyDictionary()


def _jobs() -> asyncio.Semaphore:
    """Limit on simultaneous heavy processes, one per event loop."""
    loop = asyncio.get_running_loop()
    if loop not in _JOBS:
        _JOBS[loop] = asyncio.Semaphore(int(os.environ.get("CODE_AUDIT_JOBS", "3")))
    return _JOBS[loop]

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Directories that never hold the project's own code.
JUNK_DIRS = {
    ".git", ".venv", "venv", "env", "build", "dist", "node_modules", "vendor", "__pycache__", ".tox",
    ".nox", ".mypy_cache", ".ruff_cache", ".pytest_cache", ".eggs", "site-packages", ".next", ".nuxt",
    "coverage", ".turbo", ".svelte-kit", "storage", ".idea", ".vscode", ".dart_tool",
}
TEST_DIR_NAMES = {"tests", "test", "testing", "__tests__", "e2e", "spec", "cypress"}
_TEST_FILE = re.compile(
    r"(^test_.*\.py$|.*_test\.py$|^conftest\.py$|.*\.(test|spec)\.[cm]?[jt]sx?$|.*Test\.php$|.*_test\.dart$)"
)


class AuditError(RuntimeError):
    """Failure that prevents running an engine (missing tool, timeout, invalid path)."""


@dataclass
class ToolRun:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class Unit:
    """A project detected inside the audited path (e.g. FastAPI backend, React frontend)."""

    stack: str  # python | php | node | dart
    dir: Path
    label: str  # Laravel, PHP, FastAPI, Flask, Python, React, Next.js, TypeScript, JavaScript, Flutter, Dart
    rel: str  # path relative to the audited root ("." for the root itself)

    @property
    def name(self) -> str:
        return f"{self.label} ({self.rel})"


@dataclass
class Context:
    """State shared by one `check` or `audit` run."""

    root: Path
    config: Config
    _memo: dict[Any, asyncio.Task[Any]] = field(default_factory=dict)

    def rel(self, path: str | Path, base: Path | None = None) -> str:
        p = Path(path)
        if not p.is_absolute():
            p = (base or self.root) / p
        try:
            return str(p.resolve().relative_to(self.root))
        except ValueError:
            return str(p)

    def once(self, key: Any, factory: Callable[[], Awaitable[Any]]) -> Awaitable[Any]:
        """Runs `factory` only once per key (e.g. knip serves two checks)."""
        if key not in self._memo:
            self._memo[key] = asyncio.ensure_future(factory())
        return self._memo[key]


# --------------------------------------------------------------------------- processes
async def run(cmd: list[str], cwd: Path, timeout: float = TIMEOUT_S, env: dict[str, str] | None = None) -> ToolRun:
    """Runs `cmd` without inheriting stdin (it is the MCP server's JSON-RPC channel)."""
    full_env = {
        **os.environ,
        "NO_COLOR": "1",
        "FORCE_COLOR": "0",
        "UV_NO_PROGRESS": "1",
        "PYTHONIOENCODING": "utf-8",
        "COMPOSER_NO_INTERACTION": "1",
        "npm_config_update_notifier": "false",
        "npm_config_fund": "false",
        **(env or {}),
    }
    full_env.pop("VIRTUAL_ENV", None)  # so uvx does not mistake the server's venv for the project's
    async with _jobs():
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(cwd),
                env=full_env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise AuditError(f"Could not run {cmd[0]}: {exc}") from exc
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError as exc:
            proc.kill()
            await proc.wait()
            raise AuditError(f"Timeout ({timeout:.0f}s) running {' '.join(Path(c).name for c in cmd[:3])}…") from exc
    return ToolRun(proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace"))


def which(name: str, env_var: str | None = None) -> str | None:
    return (os.environ.get(env_var) if env_var else None) or shutil.which(name)


def require_bin(name: str, hint: str, env_var: str | None = None) -> str:
    found = which(name, env_var)
    if not found:
        raise AuditError(f"`{name}` not found in PATH. {hint}")
    return found


def uvx(tool: str, *args: str) -> list[str]:
    uvx_bin = require_bin("uvx", "Install uv: https://docs.astral.sh/uv/", "CODE_AUDIT_UVX")
    return [uvx_bin, "-q", tool, *args]


def npx(package: str, *args: str) -> list[str]:
    return [require_bin("npx", "Install Node.js.", "CODE_AUDIT_NPX"), "-y", package, *args]


def tool_failure(tool: str, proc: ToolRun) -> AuditError:
    tail = (proc.stderr.strip() or proc.stdout.strip()).splitlines()[-12:]
    return AuditError(f"{tool} exited with code {proc.returncode}:\n" + "\n".join(tail))


def parse_json(tool: str, proc: ToolRun, text: str | None = None) -> Any:
    raw = proc.stdout if text is None else text
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise tool_failure(tool, proc) from exc


# --------------------------------------------------------------------------- tool cache
def cache_dir(*parts: str) -> Path:
    base = os.environ.get("CODE_AUDIT_CACHE") or os.path.join(
        os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "code-audit-mcp"
    )
    path = Path(base, *parts)
    path.mkdir(parents=True, exist_ok=True)
    return path


def project_cache(kind: str, project: Path) -> Path:
    """Cache directory specific to a project (e.g. PHPStan result cache)."""
    return cache_dir(kind, hashlib.sha1(str(project).encode()).hexdigest()[:16])


_install_locks: dict[tuple[asyncio.AbstractEventLoop, Path], asyncio.Lock] = {}


async def ensure_composer_tool(name: str, packages: list[str], binary: str) -> Path:
    """Installs PHP tools (once) in their own cache directory and returns their binary."""
    tool_dir = cache_dir("php", name)
    bin_path = tool_dir / "vendor" / "bin" / binary
    if bin_path.exists():
        return bin_path
    composer = require_bin("composer", "Install Composer: https://getcomposer.org/", "CODE_AUDIT_COMPOSER")
    lock = _install_locks.setdefault((asyncio.get_running_loop(), tool_dir), asyncio.Lock())
    async with lock:
        with open(tool_dir / ".lock", "w") as fh:  # other server processes
            await asyncio.to_thread(fcntl.flock, fh, fcntl.LOCK_EX)
            if not bin_path.exists():
                proc = await run(
                    [composer, "require", "--working-dir", str(tool_dir), "--no-interaction", "--no-progress",
                     "--quiet", *packages],
                    cwd=tool_dir,
                    timeout=600,
                )
                if proc.returncode != 0 or not bin_path.exists():
                    raise tool_failure(f"composer require {' '.join(packages)}", proc)
    return bin_path


def _platform() -> tuple[str, str]:
    system = platform.system().lower()
    arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if system not in ("linux", "darwin") or not arch:
        raise AuditError(f"Unsupported platform for downloading binaries: {platform.system()} {platform.machine()}")
    return system, arch


def _download_verified(url: str, checksums_url: str, timeout: float = 120) -> bytes:
    asset = url.rsplit("/", 1)[-1]
    with urllib.request.urlopen(checksums_url, timeout=timeout) as resp:  # nosec B310: fixed https templates
        sums = {parts[1]: parts[0] for parts in map(str.split, resp.read().decode().splitlines()) if len(parts) == 2}
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # nosec B310
        data = resp.read()
    if hashlib.sha256(data).hexdigest() != sums.get(asset):
        raise AuditError(f"The checksum of {asset} does not match the published one; not using it")
    return data


async def ensure_release_binary(name: str, version: str, url_template: str, checksums_template: str) -> Path:
    """Downloads (once) the `name` binary from a GitHub Releases .tar.gz into the cache, verifying its sha256.

    The templates receive {version}, {os} (linux|darwin) and {arch} (x64|arm64).
    """
    tool_dir = cache_dir("bin", f"{name}-{version}")
    bin_path = tool_dir / name
    if bin_path.exists():
        return bin_path
    system, arch = _platform()
    fields = {"version": version, "os": system, "arch": arch}
    lock = _install_locks.setdefault((asyncio.get_running_loop(), tool_dir), asyncio.Lock())
    async with lock:
        with open(tool_dir / ".lock", "w") as fh:
            await asyncio.to_thread(fcntl.flock, fh, fcntl.LOCK_EX)
            if not bin_path.exists():
                try:
                    data = await asyncio.to_thread(_download_verified, url_template.format(**fields),
                                                   checksums_template.format(**fields))
                except OSError as exc:
                    raise AuditError(f"Could not download {name} {version} (offline?): {exc}") from exc
                with tarfile.open(fileobj=io.BytesIO(data)) as tar:
                    member = tar.extractfile(name)  # only the binary: no tar paths
                    if member is None:
                        raise AuditError(f"The {name} package does not contain the binary")
                    tmp = tool_dir / f".{name}.tmp"
                    tmp.write_bytes(member.read())
                tmp.chmod(0o755)
                tmp.replace(bin_path)
    return bin_path


# --------------------------------------------------------------------------- paths and git
def resolve_root(path: str) -> Path:
    root = Path(path).expanduser()
    if not root.is_absolute():
        root = Path.cwd() / root
    root = root.resolve()
    if not root.exists():
        raise AuditError(f"Path does not exist: {root}")
    return root if root.is_dir() else root.parent


def git_ignored(cwd: Path, candidates: list[Path]) -> set[Path]:
    """Subset of `candidates` that git ignores (empty outside a git repo)."""
    git = shutil.which("git")
    if not git or not candidates:
        return set()
    try:
        proc = subprocess.run(
            [git, "check-ignore", "--stdin"],
            cwd=cwd,
            input="\n".join(str(c) for c in candidates),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    return {Path(line).resolve() for line in proc.stdout.splitlines() if line}


def git_tracked(cwd: Path, untracked: bool = False) -> list[str] | None:
    """Tracked files or, with `untracked`, new ones that .gitignore does not exclude (None outside git)."""
    git = shutil.which("git")
    if not git:
        return None
    args = ["ls-files", "-z", "--others", "--exclude-standard"] if untracked else ["ls-files", "-z"]
    try:
        proc = subprocess.run([git, *args], cwd=cwd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return [p for p in proc.stdout.split("\0") if p]


def is_test_path(rel_path: str) -> bool:
    parts = Path(rel_path).parts
    return any(p in TEST_DIR_NAMES for p in parts[:-1]) or bool(parts and _TEST_FILE.match(parts[-1]))


def source_children(directory: Path) -> list[Path]:
    """Direct children of `directory` that may hold the project's own code (no junk, no git-ignored paths)."""
    children = sorted(directory.iterdir())
    ignored = git_ignored(directory, children)
    return [
        c for c in children
        if c.resolve() not in ignored and not c.name.startswith(".") and c.name not in JUNK_DIRS
        and not c.name.endswith(".egg-info")
    ]


def lizard_excludes(directory: Path) -> list[str]:
    """Lizard -x patterns for junk and git-ignored directories (relative './…' paths)."""
    patterns = [f"*/{d}/*" for d in sorted(JUNK_DIRS)] + ["*.min.js", "*/public/*", "*/bootstrap/cache/*",
                                                         "*/resources/views/*"]
    children = [c for c in directory.iterdir() if c.is_dir()]
    patterns += [f"./{c.name}/*" for c in git_ignored(directory, children)]
    return patterns


def load_jsonc(text: str) -> Any:
    """JSON with comments and trailing commas (tsconfig.json, knip.jsonc)."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))


def read_json(path: Path) -> Any:
    try:
        return load_jsonc(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------- findings and results
def finding(file: str | None, line: int | None, rule: str, message: str, severity: str = "low",
            **extra: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"file": file, "line": line, "rule": rule, "severity": severity, "message": message}
    item.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    return item


def engine_result(engine: str, unit: Unit | None, findings: list[dict[str, Any]] | None = None,
                  notes: list[str] | None = None, error: str | None = None,
                  skipped: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"engine": engine, "unit": unit.name if unit else "whole project"}
    if error:
        out["error"] = error
    elif skipped:
        out["skipped"] = skipped
    else:
        out["findings"] = findings or []
    if notes:
        out["notes"] = notes
    return out


def glob_match(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)
