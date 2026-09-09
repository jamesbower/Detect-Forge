from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parent.parent / "scripts" / "bump_version.py"
_spec = importlib.util.spec_from_file_location("bump_version", _PATH)
assert _spec and _spec.loader
bv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bv)


@pytest.mark.parametrize(
    "version,part,expected",
    [
        ("0.1.0", "patch", "0.1.1"),
        ("0.1.0", "minor", "0.2.0"),
        ("0.1.9", "minor", "0.2.0"),   # minor resets patch
        ("1.2.3", "major", "2.0.0"),   # major resets minor+patch
    ],
)
def test_bump(version: str, part: str, expected: str) -> None:
    assert bv.bump(version, part) == expected


def test_bump_rejects_unknown_part() -> None:
    with pytest.raises(ValueError):
        bv.bump("0.1.0", "wibble")


def test_current_version_reads_project_table() -> None:
    text = '[build-system]\nrequires=["hatchling"]\n[project]\nname="x"\nversion = "0.3.4"\n'
    assert bv.current_version(text) == "0.3.4"


def test_set_version_replaces_once() -> None:
    text = '[project]\nname = "x"\nversion = "0.1.0"\n'
    out = bv.set_version_in_pyproject(text, "0.2.0")
    assert 'version = "0.2.0"' in out
    assert "0.1.0" not in out


def test_insert_changelog_section_between_unreleased_and_prev() -> None:
    text = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-09-09\n\nInitial.\n"
    out = bv.insert_changelog_section(text, "0.2.0", "2026-10-01")
    # New section appears, Unreleased kept, and 0.2.0 precedes 0.1.0.
    assert "## [0.2.0] - 2026-10-01" in out
    assert "## [Unreleased]" in out
    assert out.index("## [0.2.0]") < out.index("## [0.1.0]")


def test_insert_changelog_requires_unreleased() -> None:
    with pytest.raises(ValueError):
        bv.insert_changelog_section("# Changelog\n\n## [0.1.0]\n", "0.2.0", "2026-10-01")
