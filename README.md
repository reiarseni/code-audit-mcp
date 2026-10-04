# code-audit-mcp

[![CI](https://github.com/reiarseni/code-audit-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/reiarseni/code-audit-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

**Audit your whole stack with a single question to your agent.**

An MCP server (stdio) that gives Claude Code (and any MCP-compatible agent) a complete audit of your project: dead
code, dependencies, security, CVEs, complexity and lint. It covers **Laravel/PHP**, **Python (FastAPI, Flask)**,
**TypeScript/React/Next.js** and **Flutter/Dart**, including monorepos (`backend/` + `frontend/`, Laravel with React,
a Flutter app next to its backend).

> "Audit this repo" -> within a minute you get a report prioritized by severity, with false positives already
> flagged and the next step for every finding.

## Why it is different

- **Zero installation in the project.** `vendor/`, `node_modules`, the venv and `.dart_tool` stay untouched. Tools
  run through `uvx`/`npx` or from `~/.cache/code-audit-mcp`, and the first run downloads them on its own.
- **Detects stacks by itself.** It walks the repo, finds every project (even when several coexist) and audits each
  one with its native tools.
- **Built to be used by an LLM.** Findings are normalized (file, line, rule, severity, message and how to fix it),
  sorted by severity and free of the noise of ten different tools.
- **Flags false positives and explains why.** Routes registered by decorator, Laravel and Livewire hooks, Pydantic
  fields or the `HEAD` strings that bandit mistakes for passwords do not count in the summary. This way the agent
  never proposes deleting code that is in fact used.
- **Checks git history, not just the current code.** A secret committed a year ago and deleted later is still
  compromised, and it finds it.
- **Secrets never appear in the output.** They are used to group findings and to tell whether they are still in the
  code, but the value never leaves the server.

## Two tools

| Tool | Purpose |
|---|---|
| `audit(path=".")` | Overview: runs the 6 checks in parallel and returns a summary per check and per stack, totals by severity and the top findings |
| `check(name, path=".", severity, file, offset, limit, false_positives)` | Detail for one aspect: the findings of a check sorted by severity, filterable and paginated |

Checks: `dead_code` · `dependencies` · `security` · `vulnerabilities` · `complexity` · `lint`

**Context savings.** Responses are a single compact JSON (no `structuredContent` copy and no indentation). Messages
that repeat identically across several findings of a rule are emitted only once in `rules`. `check` returns 50
findings per engine (`limit`) and leaves out likely false positives (`false_positives=true` to see them). Narrow
results with `severity` (minimum) and `file` (glob or prefix, e.g. `app/Http/**`) and paginate with `offset`; the
response tells you in `next` how to continue.

## What it covers in each stack

| Check | Laravel / PHP | Python (FastAPI, Flask) | TypeScript / React / Next.js | Flutter / Dart |
|---|---|---|---|---|
| `dead_code` | PHPStan + shipmonk (understands Eloquent, Blade and Livewire) | vulture | knip | — |
| `dependencies` | composer-unused + composer-require-checker | deptry | knip | — |
| `vulnerabilities` | `composer audit` | pip-audit (venv, `uv.lock` or `requirements`) | npm / pnpm / bun audit; `yarn.lock` in OSV.dev | `pubspec.lock` in OSV.dev |
| `lint` | the project's PHPStan (with its Larastan) | ruff | the project's `tsc` + eslint | `dart analyze` with its `analysis_options.yaml` |
| `complexity` | lizard | lizard | lizard | — |
| `security` | semgrep | bandit + semgrep | semgrep | semgrep |

In every stack, `security` adds **gitleaks over the whole git history** and sensitive files that are tracked, not
ignored, or deleted but still in history.

**Flutter/Dart.** `dart analyze` needs `.dart_tool/` (`flutter pub get`); without it, it is skipped, because
generating it would write to the project. The `dart` from the Flutter SDK is used if available. The Pub ecosystem
has few advisories published in OSV: 0 CVEs does not guarantee there are none.

## Security: what generic scanners miss

On top of the public semgrep packs, it ships its own rules (`code_audit_mcp/rules/stack.yml`) for the problems of
these stacks:

- **Postgres/SQL**: SQL with interpolation or concatenation in `DB::raw/select`, `whereRaw`/`orderByRaw`…,
  `cursor.execute(f"…")`, `text(f"…")`, `pool.query(\`…${x}\`)`, `$queryRawUnsafe`; connection URLs with a
  password in the code.
- **Redis**: `KEYS` (blocks the server; use `SCAN`) and `FLUSHALL`/`FLUSHDB` in application code.
- **Laravel**: `env()` outside `config/` (breaks with `config:cache`), `$guarded = []`, `{!! !!}` in Blade, `eval`.
- **FastAPI/Flask**: `debug=True`, CORS `*` with credentials, `SECRET_KEY` in the code.
- **React**: `dangerouslySetInnerHTML`, tokens in `localStorage`.
- **Flutter/Android/iOS**: `badCertificateCallback` accepting any certificate, tokens and passwords in
  `SharedPreferences`, `usesCleartextTraffic`/`debuggable` in the release `AndroidManifest.xml` and
  `NSAllowsArbitraryLoads` in `Info.plist`.

**Secrets and sensitive files:**

- **Files**: `.env*`, private keys and certificates (`.pem`, `.key`, `.p8`, `id_rsa`, `.p12`…), credentials
  (`.pypirc`, `.netrc`, `.pgpass`, `.git-credentials`, `.htpasswd`, Android `key.properties`; `.npmrc`/`.yarnrc.yml`
  and Composer's `auth.json` only if they carry tokens), data dumps (`.sqlite`, `.db`, `*dump*.sql`, `.sql.gz`,
  `.bak`) and logs. They are reported when tracked in git, one `git add .` away from being committed (not ignored)
  and **deleted but still present in history**, with commit, author and date so you know what to rotate.
- **Secrets in history** (gitleaks): tokens and keys that were ever committed on branches, tags or remotes, even if
  they are no longer in the code. One finding per secret, with the oldest commit and whether it is still in the
  code.

## False positives

Dead-code detectors cannot see implicit usages. Every likely false positive of this kind comes out with
`likely_false_positive` and the reason, and does not count in the severity summary:

- **Python**: functions registered by decorator (`@app.get`, `@router.post`, `@bp.route`, `@command`…),
  Pydantic/SQLAlchemy/dataclass/Enum model fields, Alembic migrations, framework hooks. In dependencies, packages
  that are used without being imported (`asyncpg`/`psycopg` through the connection URL, `python-multipart`,
  `uvicorn`, `alembic`…).
- **Laravel**: Laravel/Livewire/Filament hooks, Eloquent accessors and scopes, public members of Livewire/Filament
  components and names referenced from Blade views.
- **knip**: `laravel-vite-plugin` entries (passed to knip as entry) and files of plugins that could not be loaded.
- **bandit**: `import subprocess` (B404), commands with literal arguments (`["git", "status"]`, B603/B607) and
  "passwords" that are not (`HEAD`, `refresh_token:`, uppercase constants; B105-B107).

Tests count as usage, but their findings are not reported.

## Optional configuration: `.code-audit.toml` at the project root

```toml
exclude = ["legacy/**"]                         # paths to skip
ignore = ["B404", "DEP002:ruff", "unused-method:*Resource::form"]  # rule or rule:name (globs)

[dead_code]
ignore_names = ["on_*"]
ignore_decorators = ["@command"]   # Python
min_confidence = 60                # Python (vulture)

[complexity]
threshold = 11                     # minimum cyclomatic complexity (C = 11-20, D = 21-30…)

[security]
registry = true                    # public semgrep packs (needs network)
```

## Requirements

- [uv](https://docs.astral.sh/uv/) (always).
- PHP 8.2+ and Composer for PHP projects; Node.js for JS/TS projects; bun if the project uses `bun.lock`;
  Flutter or Dart SDK for linting Dart projects.
- gitleaks downloads itself (official GitHub binary, sha256 verified) to `~/.cache/code-audit-mcp/bin`, unless it is
  already in the PATH. CVEs for `yarn.lock` and `pubspec.lock` are queried against the OSV.dev API (network).
- For complete results, the project must have its dependencies installed (`composer install`, `npm ci`, venv).
  Without them, each affected engine says so in `skipped` or `notes`.

The first run downloads the tools (a few minutes). On a large Laravel project, dead code takes 1-2 minutes; the
rest of the checks, seconds.

## Installation

Globally in Claude Code:

```bash
claude mcp add -s user code-audit /path/to/code-audit-mcp/bin/code-audit-mcp-server
```

Per project (`.mcp.json`):

```json
{
  "mcpServers": {
    "code-audit": {
      "command": "/path/to/code-audit-mcp/bin/code-audit-mcp-server",
      "args": []
    }
  }
}
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `CODE_AUDIT_TIMEOUT` | `900` | maximum seconds per tool |
| `CODE_AUDIT_JOBS` | `3` | simultaneous heavy processes |
| `CODE_AUDIT_CACHE` | `~/.cache/code-audit-mcp` | cache for PHP tools, PHPStan and gitleaks |
| `CODE_AUDIT_UVX`, `CODE_AUDIT_UV`, `CODE_AUDIT_NPX`, `CODE_AUDIT_NPM`, `CODE_AUDIT_PHP`, `CODE_AUDIT_COMPOSER`, `CODE_AUDIT_BUN`, `CODE_AUDIT_DART`, `CODE_AUDIT_FLUTTER`, `CODE_AUDIT_GITLEAKS` | from PATH | alternative binaries |

## Development

```bash
uv sync
uv run pytest
uvx ruff check .
```

Layout: `core.py` (processes, cache, finding format), `detect.py` (stacks), `config.py`,
`engines/{python,php,node,dart,shared}.py`, `checks.py` (which engine resolves each check), `server.py`.
The own semgrep rules are tested against `tests/fixtures/rules`, where every line that must be detected carries
`BAD:<rule>`.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through
[SECURITY.md](SECURITY.md). Release notes live in [CHANGELOG.md](CHANGELOG.md) and planned work in
[ROADMAP.md](ROADMAP.md). Licensed under the [MIT License](LICENSE).

---

**code-audit-mcp: the quality and security report your agent can read, prioritize and fix.**
