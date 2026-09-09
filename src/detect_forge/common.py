from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import click


def common_output_options[F: Callable[..., Any]](func: F) -> F:
    """Add `--format`, `--output`, and `--min-severity` to a click command.

    Three options are added in this order (Click applies decorators bottom-up,
    so the resulting --help order is format -> output -> min-severity):

    - ``--format`` (choice: terminal | json | html, default terminal)
    - ``--output / -o`` (Path, default None)
    - ``--min-severity`` (choice: info | low | medium | high | critical, default low)
    """
    func = click.option(
        "--min-severity",
        type=click.Choice(["info", "low", "medium", "high", "critical"]),
        default="low",
        show_default=True,
        help="Only show rules at or above this severity (info surfaces "
        "no-ATT&CK-tag and unknown-technique findings)",
    )(func)
    func = click.option(
        "--output",
        "-o",
        type=click.Path(path_type=Path),
        default=None,
        help="Write output to file instead of stdout",
    )(func)
    func = click.option(
        "--format",
        "output_format",
        type=click.Choice(["terminal", "json", "html"]),
        default="terminal",
        show_default=True,
        help="Output format",
    )(func)
    return func
