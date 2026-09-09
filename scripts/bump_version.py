#!/usr/bin/env python3
"""Bump the project version in pyproject.toml and open a new CHANGELOG section.

Usage:
    python scripts/bump_version.py patch      # 0.1.0 -> 0.1.1
    python scripts/bump_version.py minor      # 0.1.0 -> 0.2.0
    python scripts/bump_version.py major      # 0.1.9 -> 1.0.0
    python scripts/bump_version.py --set 1.2.3

Edits files but never runs git — it prints the follow-up commands so the
release stays a deliberate, reviewable act.
"""
from __future__ import annotations

import argparse
import datetime
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"

# Matches the [project] table's `version = "X.Y.Z"` line (first occurrence).
_VERSION_RE = re.compile(r'(?m)^(version\s*=\s*")(\d+\.\d+\.\d+)(")')
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SECTION = "## [{version}] - {date}\n\n### Added\n\n### Changed\n\n### Fixed\n\n"


def current_version(pyproject_text: str) -> str:
    m = _VERSION_RE.search(pyproject_text)
    if not m:
        raise ValueError("could not find a version in pyproject.toml")
    return m.group(2)


def bump(version: str, part: str) -> str:
    major, minor, patch = (int(x) for x in version.split("."))
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    if part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"unknown bump part: {part!r} (use major|minor|patch)")


def set_version_in_pyproject(text: str, new_version: str) -> str:
    new, n = _VERSION_RE.subn(rf"\g<1>{new_version}\g<3>", text, count=1)
    if n != 1:
        raise ValueError("failed to replace the version in pyproject.toml")
    return new


def insert_changelog_section(text: str, new_version: str, date: str) -> str:
    lines = text.splitlines(keepends=True)
    start = next(
        (i for i, ln in enumerate(lines) if ln.startswith("## [Unreleased]")), None
    )
    if start is None:
        raise ValueError("CHANGELOG.md is missing a '## [Unreleased]' section")
    insert_at = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("## ["):
            insert_at = i
            break
    lines.insert(insert_at, _SECTION.format(version=new_version, date=date))
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Bump the Detect-Forge version.")
    ap.add_argument("part", nargs="?", choices=["major", "minor", "patch"])
    ap.add_argument("--set", dest="set_version", help="Set an exact X.Y.Z version.")
    args = ap.parse_args(argv)

    pp_text = PYPROJECT.read_text(encoding="utf-8")
    cur = current_version(pp_text)
    if args.set_version:
        if not _SEMVER_RE.match(args.set_version):
            ap.error(f"--set expects X.Y.Z, got {args.set_version!r}")
        new = args.set_version
    elif args.part:
        new = bump(cur, args.part)
    else:
        ap.error("specify a part (major|minor|patch) or --set X.Y.Z")

    PYPROJECT.write_text(set_version_in_pyproject(pp_text, new), encoding="utf-8")
    if CHANGELOG.is_file():
        today = datetime.date.today().isoformat()
        CHANGELOG.write_text(
            insert_changelog_section(CHANGELOG.read_text(encoding="utf-8"), new, today),
            encoding="utf-8",
        )

    print(f"Bumped version {cur} -> {new}")
    print("\nNext steps:")
    print("  1. Edit CHANGELOG.md — move Unreleased notes into the new section.")
    print("  2. git add pyproject.toml CHANGELOG.md")
    print(f'  3. git commit -m "release: v{new}"')
    print(f"  4. git tag v{new} && git push && git push --tags")
    print("  5. Create a GitHub Release from the tag, then approve the 'pypi'")
    print("     environment deployment when the publish workflow pauses.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
