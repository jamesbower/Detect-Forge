from __future__ import annotations

import importlib.resources as ir


def test_py_typed_marker_present() -> None:
    """PEP 561 marker so downstream type-checkers see detect_forge's types."""
    assert ir.files("detect_forge").joinpath("py.typed").is_file()
