"""Common event schema. Flat attributes, ECS-like export."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class Event(BaseModel):
    """One normalized log row."""

    model_config = ConfigDict(extra="ignore")

    row_id: str
    ts: datetime | str | None = None
    host_name: str | None = None
    host_key: str | None = None
    user_name: str | None = None
    event_code: int
    winlog_channel: str | None = None
    process_executable: str | None = None
    process_command_line: str | None = None
    process_parent_executable: str | None = None
    target_process_executable: str | None = None
    granted_access: str | None = None
    file_path: str | None = None
    service_name: str | None = None
    service_path: str | None = None
    has_attacker_controlled_field: bool = False
    source_file: str
    raw: dict[str, Any]

    def to_ecs(self) -> dict[str, Any]:
        """Dotted ECS-like keys. Timestamps are ISO-8601 strings."""
        ts = self.ts
        if isinstance(ts, datetime):
            ts = ts.isoformat()
        return {
            "row_id": self.row_id,
            "@timestamp": ts,
            "host.name": self.host_name,
            "host_key": self.host_key,
            "user.name": self.user_name,
            "event.code": self.event_code,
            "winlog.channel": self.winlog_channel,
            "process.executable": self.process_executable,
            "process.command_line": self.process_command_line,
            "process.parent.executable": self.process_parent_executable,
            "target.process.executable": self.target_process_executable,
            "granted_access": self.granted_access,
            "file.path": self.file_path,
            "service.name": self.service_name,
            "service.path": self.service_path,
            "has_attacker_controlled_field": self.has_attacker_controlled_field,
            "source_file": self.source_file,
            "raw": self.raw,
        }


class IngestReport(BaseModel):
    """Counts for one file. Quarantine details arrive with robust ingest."""

    source_file: str
    parsed: int
    skipped: int = 0
