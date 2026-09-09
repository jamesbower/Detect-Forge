from __future__ import annotations

import hashlib
import io
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any

import pytest
import requests_mock as rm_lib

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "backtest"


def _load_synthetic_zip_bytes() -> bytes:
    return (FIXTURE_DIR / "synthetic_dataset.zip").read_bytes()


def _zip_of(members: dict[str, Any]) -> bytes:
    """Build an in-memory ZIP whose members map name -> JSON-serialisable payload."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, payload in members.items():
            zf.writestr(name, json.dumps(payload))
    return buf.getvalue()


def test_corpus_loads_builtin_index() -> None:
    from detect_forge.backtest.corpus import load_builtin_index

    idx = load_builtin_index()
    assert "datasets" in idx
    assert isinstance(idx["datasets"], dict)


def test_builtin_index_entries_are_well_formed() -> None:
    """Guard against index drift/corruption: every bundled entry must have a
    valid technique ID, an https ZIP url, and a populated sha256."""
    import re

    from detect_forge.backtest.corpus import load_builtin_index

    tid_re = re.compile(r"^T\d{4}(\.\d{3})?$")
    sha_re = re.compile(r"^[0-9a-f]{64}$")
    datasets = load_builtin_index()["datasets"]
    assert datasets, "bundled index is empty"
    seen_ids: set[str] = set()
    for tid, entries in datasets.items():
        assert tid_re.match(tid), f"bad technique id in index: {tid!r}"
        for e in entries:
            assert e["technique_id"] == tid
            assert e["url"].startswith("https://") and e["url"].endswith(".zip")
            assert sha_re.match(e.get("sha256", "")), f"bad sha256: {e['dataset_id']}"
            assert e.get("event_count", 0) > 0
            seen_ids.add(e["dataset_id"])
    assert len(seen_ids) >= 2  # non-trivial corpus


def test_corpus_datasets_for_returns_empty_for_unknown_technique(
    tmp_path: Path,
) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(
        cache_dir=tmp_path,
        index_override=fixture_idx,
    )
    assert corpus.datasets_for("T9999") == []


def test_corpus_platform_filter(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(
        cache_dir=tmp_path,
        index_override=fixture_idx,
        platform_filter={"linux"},
    )
    # T1059.001 is windows-only; filtered out.
    assert corpus.datasets_for("T1059.001") == []


def test_corpus_technique_filter(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(
        cache_dir=tmp_path,
        index_override=fixture_idx,
        technique_filter={"T1078"},
    )
    # Even though T1059.001 has datasets, the filter excludes it.
    assert corpus.datasets_for("T1059.001") == []


def test_corpus_fetches_and_caches(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx)
    datasets = corpus.datasets_for("T1059.001")
    assert len(datasets) == 1
    assert datasets[0].dataset_id == "synthetic_ps"
    assert len(datasets[0].events) == 3
    # File now in cache.
    cached = tmp_path / "security-datasets" / "datasets" / "T1059.001" / "synthetic_ps.json"
    assert cached.is_file()


def test_corpus_uses_cache_on_second_call(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx)
    corpus.datasets_for("T1059.001")
    fetch_count_before = requests_mock.call_count

    corpus2 = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx)
    corpus2.datasets_for("T1059.001")
    # Second call should not fetch (cache hit).
    assert requests_mock.call_count == fetch_count_before


def test_corpus_no_cache_refetches(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx)
    corpus.datasets_for("T1059.001")
    fetch_count_before = requests_mock.call_count

    corpus_nc = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx, no_cache=True)
    corpus_nc.datasets_for("T1059.001")
    assert requests_mock.call_count == fetch_count_before + 1


def test_corpus_source_override_skips_fetch(tmp_path: Path) -> None:
    """When source_override is set, datasets are loaded from the local path."""
    from detect_forge.backtest.corpus import MordorCorpus

    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    # Lay down a fake local checkout layout.
    src = tmp_path / "checkout"
    (src / "datasets" / "atomic" / "windows" / "execution" / "host").mkdir(parents=True)
    shutil.copy(
        FIXTURE_DIR / "synthetic_dataset.zip",
        src / "datasets" / "atomic" / "windows" / "execution" / "host" / "synthetic_ps.zip",
    )
    (src / "index.json").write_text(json.dumps(fixture_idx))

    corpus = MordorCorpus(cache_dir=tmp_path, source_override=src)
    datasets = corpus.datasets_for("T1059.001")
    assert len(datasets) == 1


def test_corpus_datasets_consulted_count(tmp_path: Path, requests_mock: rm_lib.Mocker) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    requests_mock.get(
        "https://example.invalid/synthetic_dataset.zip",
        content=_load_synthetic_zip_bytes(),
    )
    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=fixture_idx)
    corpus.datasets_for("T1059.001")
    assert corpus.datasets_consulted() == 1


def test_corpus_returns_empty_for_filtered_technique(tmp_path: Path) -> None:
    """technique_filter narrows the universe before fetch."""
    from detect_forge.backtest.corpus import MordorCorpus

    fixture_idx = json.loads((FIXTURE_DIR / "synthetic_index.json").read_text())
    corpus = MordorCorpus(
        cache_dir=tmp_path,
        index_override=fixture_idx,
        technique_filter={"T9999"},
    )
    assert corpus.datasets_for("T1059.001") == []
    assert corpus.datasets_consulted() == 0


# --------------------------------------------------------------------------
# Task 6: SHA enforcement, size caps, path safety, all-json-members (S1,S2,S3,S6)
# --------------------------------------------------------------------------


def _index_with_sha(url: str, sha: str) -> dict[str, Any]:
    return {
        "datasets": {
            "T1059": [
                {"dataset_id": "d1", "platform": "windows", "url": url, "sha256": sha}
            ]
        }
    }


def test_corpus_sha_mismatch_is_dropped_and_not_cached(
    tmp_path: Path, requests_mock: rm_lib.Mocker
) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    blob = _zip_of({"events.json": [{"a": 1}]})
    requests_mock.get("https://example.invalid/ds.zip", content=blob)
    idx = _index_with_sha("https://example.invalid/ds.zip", "deadbeef" * 8)
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=idx)
    # datasets_for swallows the per-dataset failure and returns [].
    assert corpus.datasets_for("T1059") == []
    cached = tmp_path / "security-datasets" / "datasets" / "T1059" / "d1.json"
    assert not cached.exists()  # tampered payload must not be cached


def test_corpus_sha_match_loads_and_caches(
    tmp_path: Path, requests_mock: rm_lib.Mocker
) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    payload = [{"a": 1}, {"b": 2}]
    blob = _zip_of({"events.json": payload})
    sha = hashlib.sha256(blob).hexdigest()
    requests_mock.get("https://example.invalid/ds.zip", content=blob)
    idx = _index_with_sha("https://example.invalid/ds.zip", sha)
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=idx)
    datasets = corpus.datasets_for("T1059")
    assert datasets and datasets[0].events == payload
    assert (tmp_path / "security-datasets" / "datasets" / "T1059" / "d1.json").is_file()


def test_corpus_reads_all_json_members(
    tmp_path: Path, requests_mock: rm_lib.Mocker
) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    blob = _zip_of({"part1.json": [{"a": 1}], "part2.json": [{"b": 2}]})
    requests_mock.get("https://example.invalid/ds.zip", content=blob)
    idx = _index_with_sha("https://example.invalid/ds.zip", "")
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=idx)
    datasets = corpus.datasets_for("T1059")
    assert datasets and len(datasets[0].events) == 2


def test_corpus_reads_jsonl_member(
    tmp_path: Path, requests_mock: rm_lib.Mocker
) -> None:
    """Security-Datasets store events as JSON Lines (one object per line), not a
    JSON array — the loader must parse that, else every real dataset fails."""
    from detect_forge.backtest.corpus import MordorCorpus

    jsonl = "\n".join(json.dumps({"EventID": 5158, "n": i}) for i in range(3))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("events_2020-09-04.json", jsonl)
    requests_mock.get("https://example.invalid/ds.zip", content=buf.getvalue())
    idx = _index_with_sha("https://example.invalid/ds.zip", "")
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=idx)
    datasets = corpus.datasets_for("T1059")
    assert datasets and len(datasets[0].events) == 3
    assert datasets[0].events[0]["EventID"] == 5158


def test_corpus_jsonl_skips_blank_and_bad_lines(
    tmp_path: Path, requests_mock: rm_lib.Mocker
) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    content = '{"a": 1}\n\n   \nnot json\n{"a": 2}\n'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("events.json", content)
    requests_mock.get("https://example.invalid/ds.zip", content=buf.getvalue())
    idx = _index_with_sha("https://example.invalid/ds.zip", "")
    corpus = MordorCorpus(cache_dir=tmp_path, index_override=idx)
    datasets = corpus.datasets_for("T1059")
    assert datasets and [e["a"] for e in datasets[0].events] == [1, 2]


def test_corpus_local_override_rejects_path_escape(tmp_path: Path) -> None:
    from detect_forge.backtest.corpus import MordorCorpus

    src = tmp_path / "checkout"
    src.mkdir()
    (src / "index.json").write_text(json.dumps({"datasets": {}}))
    corpus = MordorCorpus(cache_dir=tmp_path, source_override=src)
    entry = {"dataset_id": "../../etc/evil", "platform": "windows", "url": "https://x/y.zip"}
    with pytest.raises(ValueError, match="unsafe|outside|escape"):
        corpus._load_from_local_override(entry)  # noqa: SLF001
