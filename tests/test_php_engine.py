from pathlib import Path

from code_audit_mcp.core import Unit
from code_audit_mcp.engines import php

INSTALLED = {
    "laravel/framework": {"autoload": {"psr-4": {"Illuminate\\": "src/Illuminate/"}}, "require": {"ext-mbstring": "*"}},
    "filament/filament": {"autoload": {"psr-4": {"Filament\\": "src"}}, "require": {"filament/actions": "self.version"}},
    "filament/actions": {"autoload": {"psr-4": {"Filament\\Actions\\": "src"}}},
    "laravel/pint": {"autoload": {"psr-4": {"App\\": "app/"}}},  # Pint declares App\ (Laravel Zero)
    "fakerphp/faker": {"autoload": {"psr-4": {"Faker\\": "src/Faker/"}}},
}
COMPOSER = {
    "require": {"laravel/framework": "^12", "filament/filament": "^5"},
    "require-dev": {"laravel/pint": "^1", "fakerphp/faker": "^1"},
    "autoload": {"psr-4": {"App\\": "app/"}},
}


def test_classify_symbols() -> None:
    symbols = {
        "DB": [],
        "App\\Models\\Builder": [],
        "Filament\\Actions\\Action": [],
        "Filament\\Actions\\EditAction": [],
        "Faker\\Factory": [],
        "mb_substr": ["ext-mbstring"],
        "Vendor\\Ghost": [],
    }
    findings = {(f["rule"], f["name"]) : f for f in php.classify_symbols(symbols, COMPOSER, INSTALLED, "composer.json")}
    assert ("unknown-symbol", "App\\Models\\Builder") in findings  # own class: not attributed to laravel/pint
    assert "probably a wrong import" in findings[("unknown-symbol", "App\\Models\\Builder")]["message"]
    assert ("unknown-symbol", "Vendor\\Ghost") in findings
    transitive = findings[("transitive-dependency", "filament/actions")]
    assert "2 symbols" in transitive["message"] and "filament/filament" in transitive["message"]
    assert transitive["severity"] == "info"
    assert ("dev-package-in-production", "fakerphp/faker") in findings
    assert ("undeclared-extension", "ext-mbstring") in findings
    assert not any(name == "DB" for _, name in findings)


def test_false_positive_reason() -> None:
    livewire = "<?php\nclass Edit extends Component\n{\n    public $title;\n    private function helper() {}\n}\n"
    refs = {"openModal"}
    assert "convention" in php.false_positive_reason({"name": "App\\X::mount", "line": 1}, "", set())
    assert "Blade" in php.false_positive_reason({"name": "App\\X::openModal", "line": 1}, "", refs)
    assert "Livewire" in php.false_positive_reason({"name": "App\\Edit::$title", "line": 4}, livewire, set())
    assert php.false_positive_reason({"name": "App\\Edit::helper", "line": 5}, livewire, set()) is None
    assert "Eloquent" in php.false_positive_reason({"name": "App\\U::getFullNameAttribute", "line": 1}, "", set())
    assert php.false_positive_reason({"name": "App\\U::getTotals", "line": 1}, "", set()) is None


def test_view_references(tmp_path: Path) -> None:
    views = tmp_path / "resources" / "views" / "livewire"
    views.mkdir(parents=True)
    (views / "edit.blade.php").write_text(
        '<button wire:click="save">Ok</button>\n<input wire:model.live="form.email">\n'
        "{{ $user->displayName() }} @can('edit') {{ App\\Enums\\Status::label() }}\n"
    )
    refs = php.view_references(Unit("php", tmp_path, "Laravel", "."))
    assert {"save", "form", "user", "displayName", "can", "label"} <= refs


def test_dead_code_paths_and_neon_quoting(tmp_path: Path) -> None:
    for d in ("app", "routes", "tests"):
        (tmp_path / d).mkdir()
    (tmp_path / "bootstrap").mkdir()
    (tmp_path / "bootstrap" / "app.php").write_text("<?php")
    paths = php.dead_code_paths(Unit("php", tmp_path, "Laravel", "."))
    assert [Path(p).relative_to(tmp_path).as_posix() for p in paths] == ["app", "routes", "tests", "bootstrap/app.php"]
    assert php.neon_list(["/a/it's"]) == "\n    - '/a/it''s'"
