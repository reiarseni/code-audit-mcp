# Roadmap

Planned improvements, in priority order. Each one fills a gap in the [coverage table](README.md#what-it-covers-in-each-stack)
without leaving the stacks we already support (Laravel/PHP, Python, TypeScript/React, Flutter/Dart).

Every phase ships on its own branch and commit, and is done when it has: the engine function, its registration in
`checks.py`, tests and fixtures, a row in the README table, a CHANGELOG entry, and a green `ruff check` and `pytest`.

## Phase 0: feasibility spikes

Both big improvements have a risk that only shows up by running them. They are tried in a scratch folder against a
real Laravel project and a real Flutter project, before any code changes.

| Spike | What to verify | Go criteria |
|---|---|---|
| **Psalm + `psalm-plugin-laravel`** with `--taint-analysis --output-format=json` | Runs from the cache with a generated `psalm.xml`, installing nothing in the project. The plugin boots the Laravel app and might write to `storage/` or `bootstrap/cache`. | `git status` of the project identical before and after. Under 2 minutes on a medium project. At least one true positive that semgrep does not see. |
| **`dart_code_linter`** (`check-unused-code`, `check-unused-files`, `analyze`) | Runs through `dart pub global activate` with its own `PUB_CACHE`, without adding it to the project's `pubspec.yaml`. Checks for analyzer version clashes with the project's SDK. | Project untouched and stable JSON output. Few false positives on generated code (`*.g.dart`, `*.freezed.dart`) and on `main()`. |

If a spike fails, that improvement is dropped or redesigned.

## Phase 1: Laravel configuration and route rules

New rules in `rules/stack.yml`, written from scratch (the project that inspired them is AGPL-3.0, so no code is copied).

- `'debug' => true` in `config/app.php`.
- Wildcard in `VerifyCsrfToken::$except`.
- `/admin` or `/api` routes outside an `auth` middleware group.
- Login routes without `throttle`.
- `.env` values (`APP_DEBUG=true`, empty `APP_KEY`, `SESSION_SECURE_COOKIE=false`) are better read by a small Python
  check in `engines/php.py` than by semgrep, and only when the file is not versioned (a versioned one is already
  reported by `sensitive_files`).

Tests use `BAD:<rule>` fixtures under `tests/fixtures/rules`. Cost: low, no new dependencies.

## Phase 2: taint analysis for PHP

New `php.taint` engine in `engines/php.py`, registered under `security` for the `php` stack. Psalm and its Laravel
plugin are installed in the cache, as composer-unused already is.

- Each Psalm finding (`TaintedSql`, `TaintedHtml`, `TaintedShell`, `TaintedFile`, `TaintedSSRF`…) goes through
  `finding()`, with the source-to-sink trace in the message.
- Without `vendor/` the engine is reported as `skipped`, like the other PHP engines.
- Sources that Laravel already sanitizes (for instance parameterized `where()`) are flagged `likely_false_positive`,
  based on what Phase 0 shows.
- Its own timeout, because taint analysis is slow.

Cost and risk: medium. Highest value, and depends on Phase 0.

## Phase 3: Dart dead code and complexity

`dart_code_linter` as `dead_code` and `complexity` for the `dart` stack (Lizard does not support Dart). Optionally
`dependencies`, by comparing `pubspec.yaml` with the imports.

- Skipped without `.dart_tool/`, like `dart analyze`.
- Generated code (`*.g.dart`, `*.freezed.dart`, `generated/`) is excluded.
- Widgets referenced from routes or dependency injection (`GetIt`, `Provider`) are flagged `likely_false_positive`,
  because a static detector cannot see them.

This fills the three empty Flutter cells of the coverage table. Cost: medium.

## Order

1. Phase 0, to decide with data.
2. Phase 1 in parallel: it depends on nothing and is a quick win.
3. Phase 2, then Phase 3, depending on the spikes.

## Out of scope

Infrastructure as code and containers (Trivy, Checkov), DAST (ZAP), integrations (Jira, Slack), reports (SBOM, PDF)
and unmaintained Dart tools (`dartograph`, `dart_unused_files`).
