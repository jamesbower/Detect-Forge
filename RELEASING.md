# Releasing Detect-Forge to PyPI

Detect-Forge publishes via **PyPI Trusted Publishing** (OIDC) — no API tokens
are stored. A publish happens when a **GitHub Release is published**, gated by
the `pypi` GitHub Environment (branch policy + required reviewer).

## One-time setup (already done unless noted)

1. **PyPI account** for the publisher.
2. **PyPI pending Trusted Publisher** — on https://pypi.org, go to your account
   → *Publishing* → *Add a pending publisher* and enter exactly:
   - PyPI Project Name: `detect-forge`
   - Owner: `jamesbower`
   - Repository name: `Detect-Forge`
   - Workflow name: `python-publish.yml`
   - Environment name: `pypi`
3. **GitHub Environment `pypi`** — Settings → Environments → `pypi`, with a
   branch/tag policy and yourself as a Required Reviewer. *(Done.)*

## Cutting a release

1. Bump the version and open a CHANGELOG section:
   ```bash
   python scripts/bump_version.py patch     # or minor / major / --set X.Y.Z
   ```
2. Edit `CHANGELOG.md` — move the Unreleased notes into the new version section.
3. Commit, tag, and push:
   ```bash
   git add pyproject.toml CHANGELOG.md
   git commit -m "release: vX.Y.Z"
   git tag vX.Y.Z
   git push && git push --tags
   ```
4. On GitHub, **Releases → Draft a new release** → choose tag `vX.Y.Z` →
   Publish. This triggers `python-publish.yml`.
5. The publish job pauses on the `pypi` environment — **Approve** the deployment.
6. Verify: https://pypi.org/project/detect-forge/ shows the new version, and
   `pip install detect-forge==X.Y.Z` works in a clean venv.

## Notes

- **PyPI versions are immutable.** A bad upload can't be replaced — bump to the
  next patch and yank the bad version on PyPI.
- The release build runs `pytest`, `python -m build`, `twine check`, and a
  tag↔version check before anything is uploaded; a mismatch fails the release.
