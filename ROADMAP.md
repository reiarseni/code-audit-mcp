# Roadmap

Planned improvements, in priority order. Each one fills a gap in the [coverage table](README.md#what-it-covers-in-each-stack)
without leaving the stacks we already support (Laravel/PHP, Python, TypeScript/React, Flutter/Dart) and the Docker
files that ship with them.

Every phase ships on its own branch and commit. Each one starts with a short spike, run against real projects before
any code changes, with an explicit go / no-go criterion. If the spike fails, the phase is dropped or redesigned.
A phase is done when it has: the engine function, its registration in `checks.py`, tests and fixtures, a row in the
README table, a CHANGELOG entry, and a green `ruff check` and `pytest`.

## Phase 1: Docker (top priority)

Best value for the cost: the tools are mature and maintained, it covers all four stacks at once, and the own rules
close the most common leak in images, which no existing scanner covers. It fits the current design as root engines,
like `gitleaks`.

**Spike.** Run `hadolint` and `compose-lint` over two or three real projects. Go if the noise is manageable and the
output (`hadolint --format json`, `compose-lint` JSON) normalizes cleanly into `finding()`.

**Engines**

- `detect.py` locates `Dockerfile*`, `*.dockerfile`, `compose*.y*ml`, `docker-compose*.y*ml` and `.dockerignore`.
- `lint`: [hadolint](https://github.com/hadolint/hadolint) over every Dockerfile (92 `DL` rules plus ShellCheck on
  `RUN`). Verified binary download into the cache, like gitleaks. It is GPL-3.0 and runs as a subprocess, so it does
  not affect our MIT license.
- `security`: [compose-lint](https://github.com/tmatens/compose-lint) (MIT, via `uvx`) over every Compose file:
  `privileged`, mounted Docker socket, missing `cap_drop` and `no-new-privileges`, wildcard port binds, unpinned
  images, plaintext credentials in `environment:`.

**Own rules** (nobody covers them), in `rules/stack.yml` or a small Python check:

- `COPY . .` without a `.dockerignore`, or with one that does not exclude `.env`, `.git`, `vendor/`, `node_modules/`
  or `.dart_tool/`.
- Secrets in `ARG` or `ENV`: `APP_KEY`, `DB_PASSWORD`, `SECRET_KEY`, tokens.
- Laravel: `composer install` without `--no-dev` in the final stage, `php artisan serve` in `CMD`, `APP_DEBUG=true`
  in the image.
- Python: `pip install` without `--no-cache-dir`, `uvicorn --reload` or `flask run` in production.
- Node: `npm install` instead of `npm ci`, `NODE_ENV` unset, process running as root.
- Compose: plaintext Postgres or Redis passwords, Redis without a password and with its port exposed, `.env` mounted
  as a volume.

Cost: low to medium. Out of this phase: base-image CVEs, because analyzing an image without pulling it is not possible.

## Phase 2: Laravel configuration and route rules

New rules in `rules/stack.yml`, written from scratch (the project that inspired them is AGPL-3.0, so no code is copied).

**Spike.** Run the rules over one or two real Laravel projects. Go if they find real issues without flooding the
report.

- `'debug' => true` in `config/app.php`.
- Wildcard in `VerifyCsrfToken::$except`.
- `/admin` or `/api` routes outside an `auth` middleware group.
- Login routes without `throttle`.
- `.env` values (`APP_DEBUG=true`, empty `APP_KEY`, `SESSION_SECURE_COOKIE=false`) are better read by a small Python
  check in `engines/php.py` than by semgrep, and only when the file is not versioned (a versioned one is already
  reported by `sensitive_files`).

Tests use `BAD:<rule>` fixtures under `tests/fixtures/rules`. Cost: low, no new dependencies.

## Phase 3: taint analysis for PHP

New `php.taint` engine in `engines/php.py`, registered under `security` for the `php` stack, using Psalm with
`psalm-plugin-laravel`, installed in the cache as composer-unused already is. Highest technical value (data flows
that semgrep cannot see), and the riskiest.

**Spike.** Run Psalm with `--taint-analysis --output-format=json` from the cache with a generated `psalm.xml`.
The plugin boots the Laravel app and might write to `storage/` or `bootstrap/cache`. Go if: `git status` of the
project is identical before and after, it takes under 2 minutes on a medium project, and it finds at least one true
positive that semgrep does not.

- Each Psalm finding (`TaintedSql`, `TaintedHtml`, `TaintedShell`, `TaintedFile`, `TaintedSSRF`…) goes through
  `finding()`, with the source-to-sink trace in the message.
- Without `vendor/` the engine is reported as `skipped`, like the other PHP engines.
- Sources that Laravel already sanitizes (for instance parameterized `where()`) are flagged `likely_false_positive`,
  based on what the spike shows.
- Its own timeout, because taint analysis is slow.

Cost and risk: medium. If the spike fails, this phase is removed.

## Phase 4: Dart dead code and complexity

`dart_code_linter` as `dead_code` and `complexity` for the `dart` stack (Lizard does not support Dart). Optionally
`dependencies`, by comparing `pubspec.yaml` with the imports. It fills the three empty Flutter cells of the coverage
table, but it adds less than the phases above and is the most likely to be unviable.

**Spike.** Run `dart_code_linter` (`check-unused-code`, `check-unused-files`, `analyze`) through
`dart pub global activate` with its own `PUB_CACHE`, without adding it to the project's `pubspec.yaml`. Go if the
project stays untouched, there is no analyzer version clash with the project's SDK, the JSON output is stable, and
there are few false positives on generated code and on `main()`.

- Skipped without `.dart_tool/`, like `dart analyze`.
- Generated code (`*.g.dart`, `*.freezed.dart`, `generated/`) is excluded.
- Widgets referenced from routes or dependency injection (`GetIt`, `Provider`) are flagged `likely_false_positive`,
  because a static detector cannot see them.

Cost: medium. Willing to drop it if the spike fails.

## Out of scope

- Analysis of already-built images and the host (Dockle, dive, docker-bench-security, Docker Scout, `trivy image`)
  and CVEs of base images: they are not static.
- Other infrastructure as code (Terraform, Kubernetes, CloudFormation) and the generic scanners that cover it
  (Trivy, Checkov).
- DAST (ZAP), integrations (Jira, Slack) and reports (SBOM, PDF).
- Unmaintained tools: `dartograph`, `dart_unused_files`, `dockerfilelint`.
