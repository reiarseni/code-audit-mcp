import json
from pathlib import Path

import pytest

from code_audit_mcp.config import Config
from code_audit_mcp.core import Context, Unit
from code_audit_mcp.engines import node


@pytest.mark.parametrize("path, plugin", [
    ("/p/playwright.config.ts", "playwright"),
    ("/p/.eslintrc.cjs", "eslint"),
    ("/p/vite.config.mts", "vite"),
    ("/p/next.config.js", "next"),
])
def test_plugin_from_config(path: str, plugin: str) -> None:
    assert node.plugin_from_config(path) == plugin


def test_vite_inputs_laravel_plugin(tmp_path: Path) -> None:
    for f in ("resources/css/app.css", "resources/js/app.js", "resources/js/admin.ts"):
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("")
    (tmp_path / "vite.config.js").write_text(
        "export default defineConfig({ plugins: [laravel({\n  input: ['resources/css/app.css', "
        "'resources/js/app.js', \"resources/js/missing.js\"],\n refresh: true })] })"
    )
    assert node.vite_inputs(Unit("node", tmp_path, "JavaScript", ".")) == ["resources/css/app.css", "resources/js/app.js"]
    (tmp_path / "vite.config.js").write_text("laravel(['resources/js/admin.ts'])")
    assert node.vite_inputs(Unit("node", tmp_path, "JavaScript", ".")) == ["resources/js/admin.ts"]


def test_dead_from_knip_marks_disabled_plugin_files(tmp_path: Path) -> None:
    unit = Unit("node", tmp_path, "Next.js", "web")
    ctx = Context(tmp_path.parent.resolve(), Config())
    data = {
        "files": ["playwright.config.ts", "e2e/fixtures.ts", "src/Old.tsx"],
        "issues": [{
            "file": "src/lib.ts",
            "exports": [{"name": "helper", "line": 3}],
            "types": [{"name": "Props", "line": 9}],
            "enumMembers": {"Color": [{"name": "Red", "line": 12}]},
            "duplicates": [[{"name": "a"}, {"name": "default"}]],
            "dependencies": [{"name": "lodash", "line": 4}],
        }],
    }
    findings = node.dead_from_knip(data, unit, ctx, disabled=["playwright"])
    by_name = {f["name"]: f for f in findings}
    prefix = f"{tmp_path.name}/"
    assert by_name["playwright.config.ts"]["likely_false_positive"]
    assert by_name["fixtures.ts"]["likely_false_positive"]
    assert "likely_false_positive" not in by_name["Old.tsx"] and by_name["Old.tsx"]["file"] == prefix + "src/Old.tsx"
    assert by_name["helper"]["rule"] == "unused-export" and by_name["helper"]["line"] == 3
    assert by_name["Color.Red"]["rule"] == "unused-enum-member"
    assert by_name["a = default"]["rule"] == "duplicate-export"
    assert "lodash" not in by_name  # dependencies belong to the dependencies check


def test_parse_npm_audit_keeps_only_direct_advisories() -> None:
    data = {"vulnerabilities": {
        "next": {"severity": "critical", "isDirect": True, "range": "<15.2", "via": [
            {"title": "Cache confusion", "url": "https://github.com/advisories/GHSA-aaaa"}],
            "fixAvailable": {"name": "next", "version": "15.2.1", "isSemVerMajor": False}},
        "shadcn": {"severity": "high", "via": ["braces"], "fixAvailable": True},
        "braces": {"severity": "moderate", "range": "*", "via": [{"title": "ReDoS", "url": "x/GHSA-bbbb"}],
                   "fixAvailable": False},
    }}
    findings = node.parse_npm_audit(data, "package-lock.json")
    assert [(f["rule"], f["severity"]) for f in findings] == [("GHSA-aaaa", "critical"), ("GHSA-bbbb", "medium")]
    assert findings[0]["fix"] == "upgrade next to 15.2.1" and findings[1]["fix"] == "no fix available"


def test_parse_bun_and_pnpm_audit() -> None:
    bun = {"uuid": [{"id": 1, "url": "https://github.com/advisories/GHSA-w5hq", "title": "Bounds",
                     "severity": "moderate", "vulnerable_versions": "<11.1.1"}]}
    assert node.parse_bun_audit(bun, "bun.lock")[0]["rule"] == "GHSA-w5hq"
    pnpm = {"advisories": {"1": {"module_name": "axios", "severity": "high", "title": "SSRF",
                                 "github_advisory_id": "GHSA-cccc", "vulnerable_versions": "<1.7",
                                 "patched_versions": ">=1.7.4"}}}
    f = node.parse_pnpm_audit(pnpm, "pnpm-lock.yaml")[0]
    assert (f["rule"], f["severity"], f["fix"]) == ("GHSA-cccc", "high", "upgrade to >=1.7.4")


def test_tsconfig_targets_solution_style(tmp_path: Path) -> None:
    (tmp_path / "tsconfig.json").write_text(json.dumps(
        {"files": [], "references": [{"path": "./tsconfig.app.json"}, {"path": "./tsconfig.node.json"}]}))
    (tmp_path / "tsconfig.app.json").write_text("{}")
    (tmp_path / "tsconfig.node.json").write_text("{}")
    assert node.tsconfig_targets(Unit("node", tmp_path, "React", ".")) == ["tsconfig.app.json", "tsconfig.node.json"]
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions": {"strict": true}, // x\n}')
    assert node.tsconfig_targets(Unit("node", tmp_path, "React", ".")) == ["tsconfig.json"]


def test_tsc_line_regex() -> None:
    m = node.TSC_LINE.match("src/app/page.tsx(12,5): error TS2322: Type 'string' is not assignable to type 'number'.")
    assert m and (m["file"], m["line"], m["code"]) == ("src/app/page.tsx", "12", "TS2322")


YARN_V1 = '''# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz"

lodash@^4.17.15:
  version "4.17.15"

"string-width-cjs@npm:string-width@^4.2.0":
  version "4.2.3"

my-lib@file:../my-lib:
  version "1.0.0"
'''

YARN_BERRY = '''__metadata:
  version: 8
  cacheKey: 10c0

"lodash@npm:^4.17.15, lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"@scope/pkg@npm:1.2.3":
  version: 1.2.3

"app@workspace:.":
  version: 0.0.0-use.local
'''


def test_parse_yarn_lock_v1_and_berry() -> None:
    assert node.parse_yarn_lock(YARN_V1) == [("@babel/code-frame", "7.12.13"), ("lodash", "4.17.15"),
                                             ("string-width", "4.2.3")]
    assert node.parse_yarn_lock(YARN_BERRY) == [("@scope/pkg", "1.2.3"), ("lodash", "4.17.21")]
