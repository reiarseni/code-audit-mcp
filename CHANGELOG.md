# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-04

### Added
- `audit` and `check` MCP tools with six checks: `dead_code`, `dependencies`,
  `security`, `vulnerabilities`, `complexity` and `lint`.
- Engines for Laravel/PHP, Python (FastAPI, Flask), TypeScript/React/Next.js
  and Flutter/Dart, including monorepo detection.
- Security rules for Postgres, Redis, Laravel, FastAPI/Flask, React and
  Flutter mobile manifests.
- gitleaks over the full git history and detection of sensitive files that
  are tracked, unignored or deleted but still in history.
- CVE lookups through OSV.dev for `yarn.lock` and `pubspec.lock`.
- Likely false positive flags with a reason for implicit usages.
- Optional `.code-audit.toml` per project.

### Changed
- Compact JSON responses with paginated findings to reduce agent context use.
