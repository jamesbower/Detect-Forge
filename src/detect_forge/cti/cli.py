from __future__ import annotations

import click

from .._stubs import stub_command

_INGEST_MESSAGE = (
    "detect-forge: 'cti ingest' is not yet implemented.\n"
    "Ship target: Q3-Q4 2026.\n"
    "Track at https://github.com/jamesbower/Detect-Forge/issues"
)


@click.group(name="cti")
def cti_group() -> None:
    """CTI-to-detection generation (not yet implemented)."""


cti_ingest_cmd = stub_command(
    "ingest",
    _INGEST_MESSAGE,
    help_text="Generate detections from a CTI report (not yet implemented).",
)
cti_group.add_command(cti_ingest_cmd)


def register(group: click.Group) -> None:
    group.add_command(cti_group)
