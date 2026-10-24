"""JSONL adapter driven by config/field_map.yaml."""

from __future__ import annotations

import hashlib
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import orjson
import yaml

from titanlog.schema import Event, IngestReport

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_FIELD_MAP = "config/field_map.yaml"
_EMPTY = {"", "-"}
_ATTR = {
    "host.name": "host_name",
    "user.name": "user_name",
    "event.code": "event_code",
    "@timestamp": "ts",
    "winlog.channel": "winlog_channel",
    "process.executable": "process_executable",
    "process.command_line": "process_command_line",
    "process.parent.executable": "process_parent_executable",
    "target.process.executable": "target_process_executable",
    "granted_access": "granted_access",
    "file.path": "file_path",
    "service.name": "service_name",
    "service.path": "service_path",
}

FieldMap = dict[str, tuple[str, ...]]


def stable_row_id(source_file: str, line_no: int) -> str:
    """Stable id for a physical line. Not Python's salted hash()."""
    payload = f"{source_file}:{line_no}".encode()
    return hashlib.sha256(payload).hexdigest()


def host_key_for(host_name: str | None) -> str | None:
    """casefold the host and drop a DNS or NetBIOS domain."""
    if host_name is None:
        return None
    text = host_name.strip()
    if "\\" in text:
        text = text.split("\\")[-1].strip()
    if "." in text:
        text = text.split(".", 1)[0].strip()
    text = text.casefold()
    if text in _EMPTY:
        return None
    return text


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


def first_present(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key not in record or record[key] is None:
            continue
        value = record[key]
        if isinstance(value, str) and value.strip() in _EMPTY:
            continue
        return value
    return None


def first_text(record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    value = first_present(record, keys)
    if value is None:
        return None
    text = str(value).strip()
    if text in _EMPTY:
        return None
    return text


def parse_timestamp(value: str | None) -> datetime | str | None:
    """Parse a timestamp. Unparsed values stay as text."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return text


def resolve_field_map(path: str | Path = _DEFAULT_FIELD_MAP) -> Path:
    candidate = Path(path)
    if candidate.is_file():
        return candidate
    rooted = _REPO_ROOT / candidate
    if rooted.is_file():
        return rooted
    return candidate


@lru_cache(maxsize=8)
def load_field_map(path: str) -> FieldMap:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError(f"Field map must be a mapping: {path}")
    parsed: FieldMap = {}
    for target, keys in raw.items():
        name = str(target)
        if name not in _ATTR:
            raise ValueError(f"Unknown target field: {name}")
        if not isinstance(keys, list) or not all(isinstance(key, str) for key in keys):
            raise TypeError(f"{name} must be a list of source key names")
        if not keys:
            raise ValueError(f"{name} needs at least one source key")
        parsed[name] = tuple(keys)
    if "event.code" not in parsed:
        raise ValueError("Field map requires event.code")
    return parsed


def event_from_record(
    record: dict[str, Any],
    *,
    source_file: str,
    line_no: int,
    field_map: FieldMap | None = None,
) -> Event | None:
    mapping = field_map if field_map is not None else load_field_map(str(resolve_field_map()))
    event_code = coerce_event_code(first_present(record, mapping["event.code"]))
    if event_code is None:
        return None
    values: dict[str, Any] = {"event_code": event_code}
    for target, keys in mapping.items():
        if target == "event.code":
            continue
        if target == "@timestamp":
            text = first_text(record, keys)
            values["ts"] = parse_timestamp(text)
            continue
        values[_ATTR[target]] = first_text(record, keys)
    command_line = values.get("process_command_line")
    service_path = values.get("service_path")
    file_path = values.get("file_path")
    return Event(
        row_id=stable_row_id(source_file, line_no),
        ts=values.get("ts"),
        host_name=values.get("host_name"),
        host_key=host_key_for(values.get("host_name")),
        user_name=values.get("user_name"),
        event_code=event_code,
        winlog_channel=values.get("winlog_channel"),
        process_executable=values.get("process_executable"),
        process_command_line=command_line,
        process_parent_executable=values.get("process_parent_executable"),
        target_process_executable=values.get("target_process_executable"),
        granted_access=values.get("granted_access"),
        file_path=file_path,
        service_name=values.get("service_name"),
        service_path=service_path,
        has_attacker_controlled_field=any((command_line, service_path, file_path)),
        source_file=source_file,
        raw=record,
    )


class GenericJsonlAdapter:
    """Map JSONL with an ordered YAML field map."""

    def __init__(self, field_map_path: str | Path = _DEFAULT_FIELD_MAP) -> None:
        self.field_map_path = resolve_field_map(field_map_path)
        self.field_map = load_field_map(str(self.field_map_path))

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
            event = event_from_record(
                record,
                source_file=source_file,
                line_no=line_no,
                field_map=self.field_map,
            )
            if event is None:
                skipped += 1
                continue
            events.append(event)
        report = IngestReport(source_file=source_file, parsed=len(events), skipped=skipped)
        return events, report
