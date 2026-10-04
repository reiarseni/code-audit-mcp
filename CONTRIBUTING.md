# Contributing

Thanks for helping improve code-audit-mcp.

## Setup

```bash
git clone https://github.com/reiarseni/code-audit-mcp
cd code-audit-mcp
uv sync
uv run pytest
uvx ruff check .
```

## Guidelines

- Keep the server read-only on the audited project and never print secret
  values.
- Add a test for every new behavior. Custom semgrep rules are tested against
  `tests/fixtures/rules`, where each line that must match carries
  `BAD:<rule-id>`.
- Prefer flagging a probable false positive with a reason over silently
  dropping a finding.
- Write commits as `type: description` (`feat`, `fix`, `docs`, `chore`,
  `refactor`, `test`), in English, imperative mood, 72 characters at most.
- Open an issue before large changes.
