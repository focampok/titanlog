"""Adapter contract: every log source becomes Event rows."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from titanlog.schema import Event, IngestReport


class Adapter(Protocol):
    def to_events(self, path: str | Path) -> tuple[list[Event], IngestReport]:
        """Read one file and return normalized events plus a short report."""
