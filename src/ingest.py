"""Load a directory of OTRF JSONL files into one DataFrame."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd

from titanlog.adapters.otrf_sysmon import OtrfSysmonAdapter
from titanlog.schema import Event

COLUMNS = [
    "row_id",
    "ts",
    "host_name",
    "host_key",
    "user_name",
    "event_code",
    "winlog_channel",
    "process_executable",
    "process_command_line",
    "process_parent_executable",
    "target_process_executable",
    "granted_access",
    "file_path",
    "service_name",
    "service_path",
    "has_attacker_controlled_field",
    "source_file",
]


def event_to_row(event: Event) -> dict[str, object]:
    ts = event.ts.isoformat() if isinstance(event.ts, datetime) else event.ts
    return {
        "row_id": event.row_id,
        "ts": ts,
        "host_name": event.host_name,
        "host_key": event.host_key,
        "user_name": event.user_name,
        "event_code": event.event_code,
        "winlog_channel": event.winlog_channel,
        "process_executable": event.process_executable,
        "process_command_line": event.process_command_line,
        "process_parent_executable": event.process_parent_executable,
        "target_process_executable": event.target_process_executable,
        "granted_access": event.granted_access,
        "file_path": event.file_path,
        "service_name": event.service_name,
        "service_path": event.service_path,
        "has_attacker_controlled_field": event.has_attacker_controlled_field,
        "source_file": event.source_file,
    }


def load_dir(directory: str | Path = "data/otrf") -> pd.DataFrame:
    """Read every .json and .jsonl file in directory through OtrfSysmonAdapter."""
    root = Path(directory)
    if not root.is_dir():
        return pd.DataFrame(columns=COLUMNS)
    adapter = OtrfSysmonAdapter()
    rows: list[dict[str, object]] = []
    for path in sorted(root.iterdir()):
        if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl"}:
            continue
        events, _report = adapter.to_events(path)
        rows.extend(event_to_row(event) for event in events)
    return pd.DataFrame(rows, columns=COLUMNS)
