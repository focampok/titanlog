"""OTRF Security-Datasets JSONL (Sysmon and Windows channels) → Event."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any

import orjson

from titanlog.schema import Event, IngestReport

_USER_KEYS = ("SubjectUserName", "User", "TargetUserName")
_TIMESTAMP_KEYS = ("UtcTime", "@timestamp")
_SERVICE_PATH_KEYS = ("ServiceFileName", "ImagePath")
_EMPTY = {"", "-"}


def stable_row_id(source_file: str, line_no: int) -> str:
    """Stable id for a physical line. Not Python's salted hash()."""
    payload = f"{source_file}:{line_no}".encode()
    return hashlib.sha256(payload).hexdigest()


def coerce_event_code(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        body = text[1:] if text.startswith(("+", "-")) else text
        if body.isdigit():
            return int(text)
    return None


def first_text(record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        if key not in record or record[key] is None:
            continue
        text = str(record[key]).strip()
        if text in _EMPTY:
            continue
        return text
    return None


def parse_timestamp(value: str | None) -> datetime | str | None:
    """Parse UtcTime or @timestamp. Unparsed values stay as text."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return text


def event_from_record(
    record: dict[str, Any],
    *,
    source_file: str,
    line_no: int,
) -> Event | None:
    event_code = coerce_event_code(record.get("EventID"))
    if event_code is None:
        return None
    return Event(
        row_id=stable_row_id(source_file, line_no),
        ts=parse_timestamp(first_text(record, _TIMESTAMP_KEYS)),
        host_name=first_text(record, ("Hostname",)),
        user_name=first_text(record, _USER_KEYS),
        event_code=event_code,
        winlog_channel=first_text(record, ("Channel",)),
        process_executable=first_text(record, ("Image",)),
        process_command_line=first_text(record, ("CommandLine",)),
        process_parent_executable=first_text(record, ("ParentImage",)),
        target_process_executable=first_text(record, ("TargetImage",)),
        granted_access=first_text(record, ("GrantedAccess",)),
        file_path=first_text(record, ("TargetFilename",)),
        service_name=first_text(record, ("ServiceName",)),
        service_path=first_text(record, _SERVICE_PATH_KEYS),
        source_file=source_file,
        raw=record,
    )


class OtrfSysmonAdapter:
    """Map one OTRF JSONL file. Line numbers are 1-based and stable."""

    def to_events(self, path: str | Path) -> tuple[list[Event], IngestReport]:
        file_path = Path(path)
        source_file = file_path.name
        events: list[Event] = []
        skipped = 0
        for line_no, raw_line in enumerate(file_path.read_bytes().splitlines(), start=1):
            if not raw_line.strip():
                continue
            try:
                record = orjson.loads(raw_line)
            except orjson.JSONDecodeError:
                skipped += 1
                continue
            if not isinstance(record, dict):
                skipped += 1
                continue
            event = event_from_record(record, source_file=source_file, line_no=line_no)
            if event is None:
                skipped += 1
                continue
            events.append(event)
        report = IngestReport(source_file=source_file, parsed=len(events), skipped=skipped)
        return events, report
