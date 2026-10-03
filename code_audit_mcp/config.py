"""Optional configuration of the audited project: `.code-audit.toml` at its root.

```toml
exclude = ["legacy/**"]                       # paths to skip (globs)
ignore = ["B404", "unused-export", "DEP002:ruff", "unused-method:*Resource::form"]  # rule or rule:name

[dead_code]
ignore_names = ["on_*"]          # names to ignore (globs)
ignore_decorators = ["@command"] # Python: functions registered by these decorators
min_confidence = 60              # Python/vulture

[complexity]
threshold = 11                   # minimum cyclomatic complexity to report

[security]
registry = true                  # also use the public semgrep packs (needs network)
```
"""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_FILE = ".code-audit.toml"


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    ignore: list[str] = field(default_factory=list)
    ignore_names: list[str] = field(default_factory=list)
    ignore_decorators: list[str] = field(default_factory=list)
    min_confidence: int = 60
    complexity_threshold: int = 11
    registry: bool = True
    source: str | None = None
    warnings: list[str] = field(default_factory=list)

    def is_ignored(self, item: dict[str, Any]) -> bool:
        """True if the finding falls under `exclude`, `ignore` or `ignore_names`."""
        file = item.get("file") or ""
        if file and any(fnmatch.fnmatchcase(file, p) or file.startswith(p.rstrip("*/") + "/") for p in self.exclude):
            return True
        rule, name = str(item.get("rule", "")), str(item.get("name") or "")
        for entry in self.ignore:
            pattern_rule, _, pattern_name = entry.partition(":")
            if fnmatch.fnmatchcase(rule, pattern_rule) and (not pattern_name or fnmatch.fnmatchcase(name, pattern_name)):
                return True
        if name and self.ignore_names:
            short = name.rsplit("::", 1)[-1].lstrip("$")
            return any(fnmatch.fnmatchcase(short, p) or fnmatch.fnmatchcase(name, p) for p in self.ignore_names)
        return False


def load_config(root: Path) -> Config:
    path = root / CONFIG_FILE
    if not path.exists():
        return Config()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return Config(warnings=[f"{CONFIG_FILE} could not be read and is ignored: {exc}"])
    dead = data.get("dead_code", {})
    return Config(
        exclude=[str(p) for p in data.get("exclude", [])],
        ignore=[str(p) for p in data.get("ignore", [])],
        ignore_names=[str(p) for p in dead.get("ignore_names", [])],
        ignore_decorators=[str(p) for p in dead.get("ignore_decorators", [])],
        min_confidence=int(dead.get("min_confidence", 60)),
        complexity_threshold=int(data.get("complexity", {}).get("threshold", 11)),
        registry=bool(data.get("security", {}).get("registry", True)),
        source=str(path),
    )
