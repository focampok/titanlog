"""Load OTRF JSONL and reject unexpected input without guessing a verdict."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import orjson
import pandas as pd

from detectors import detect
from titanlog.adapters.generic_jsonl import (
    coerce_event_code,
    event_from_record,
    first_present,
    load_field_map,
    resolve_field_map,
)
from titanlog.adapters.otrf_sysmon import OtrfSysmonAdapter
from titanlog.schema import Event, IngestReport

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_QUARANTINE = _REPO_ROOT / "data" / "quarantine"
_FIELD_LIMIT = 64 * 1024

# Sysmon schema IDs 1–29, plus every EventID present in the P0 OTRF files.
# Any other id is unknown: skip, count, quarantine. Do not invent a meaning.
_P0_WINDOWS_EVENT_IDS = {
    129,
    400,
    600,
    800,
    1102,
    4103,
    4104,
    4624,
    4627,
    4634,
    4656,
    4658,
    4662,
    4663,
    4670,
    4672,
    4673,
    4674,
    4688,
    4689,
    4690,
    4697,
    4703,
    4769,
    5140,
    5145,
    5156,
    5158,
    5857,
    7000,
    7009,
    7036,
    7040,
    7045,
    40961,
    40962,
    53504,
}
_KNOWN_EVENT_IDS = set(range(1, 30)) | _P0_WINDOWS_EVENT_IDS

# huge_field is counted and quarantined, and the truncated row is kept.
_KEPT_WITH_FLAG = {"huge_field"}

REASONS = (
    "malformed_json",
    "missing_fields",
    "unknown_event_id",
    "empty_file",
    "huge_field",
    "non_windows",
    "json_array",
)

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
    "truncated",
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
        "truncated": event.truncated,
        "source_file": event.source_file,
    }


def _bump(counts: dict[str, int], reason: str) -> None:
    counts[reason] = counts.get(reason, 0) + 1


def _truncate_text(value: str) -> tuple[str, bool]:
    raw = value.encode("utf-8")
    if len(raw) <= _FIELD_LIMIT:
        return value, False
    return raw[:_FIELD_LIMIT].decode("utf-8", errors="ignore"), True


def _truncate_record(record: dict[str, object]) -> tuple[dict[str, object], bool]:
    truncated = False
    cleaned: dict[str, object] = {}
    for key, value in record.items():
        if isinstance(value, str):
            shortened, did = _truncate_text(value)
            cleaned[key] = shortened
            truncated = truncated or did
        else:
            cleaned[key] = value
    return cleaned, truncated


def matches_known_pattern(event: Event) -> bool:
    """True when a P0 detector hits. This is not a severity verdict."""
    return bool(detect([event]))


def _skip_reason(
    record: dict[str, object],
    *,
    source_keys: set[str],
    field_map: dict[str, tuple[str, ...]],
) -> tuple[str | None, int | None]:
    if not any(key in record for key in source_keys):
        return "non_windows", None
    event_code = coerce_event_code(first_present(record, field_map["event.code"]))
    host = first_present(record, field_map["host.name"])
    if event_code is None or host is None:
        return "missing_fields", None
    if event_code not in _KNOWN_EVENT_IDS:
        return "unknown_event_id", event_code
    return None, None


def _write_quarantine(
    directory: Path,
    source_name: str,
    reason: str,
    blobs: list[bytes],
) -> str | None:
    if not blobs:
        return None
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{Path(source_name).name}.{reason}.jsonl"
    body = b"\n".join(blobs)
    if body and not body.endswith(b"\n"):
        body += b"\n"
    target.write_bytes(body)
    return str(target)


def _empty_report(source_name: str, *, reason: str | None, quarantine: str | None) -> IngestReport:
    reasons = {reason: 1} if reason else {}
    paths = [quarantine] if quarantine else []
    skipped = 1 if reason and reason not in _KEPT_WITH_FLAG else 0
    return IngestReport(
        parsed=0,
        skipped_by_reason=reasons,
        quarantined_path=paths,
        unknown_event_ids=[],
        status="insufficient_evidence",
        source_file=source_name,
        skipped=skipped,
    )


def ingest_file(
    path: str | Path,
    *,
    quarantine_dir: str | Path | None = None,
) -> tuple[pd.DataFrame, IngestReport]:
    """Read one JSON/JSONL file. Bad input is skipped, counted, and quarantined."""
    file_path = Path(path)
    source_name = file_path.name or "upload"
    quarantine_root = Path(quarantine_dir) if quarantine_dir else _DEFAULT_QUARANTINE
    try:
        raw = file_path.read_bytes()
    except OSError:
        return pd.DataFrame(columns=COLUMNS), _empty_report(source_name, reason=None, quarantine=None)

    if not raw.strip():
        quarantine = _write_quarantine(quarantine_root, source_name, "empty_file", [b""])
        return pd.DataFrame(columns=COLUMNS), _empty_report(
            source_name, reason="empty_file", quarantine=quarantine
        )

    stripped = raw.lstrip()
    if stripped.startswith(b"["):
        try:
            payload = orjson.loads(raw)
        except orjson.JSONDecodeError:
            payload = None
        if isinstance(payload, list):
            quarantine = _write_quarantine(quarantine_root, source_name, "json_array", [raw])
            return pd.DataFrame(columns=COLUMNS), _empty_report(
                source_name, reason="json_array", quarantine=quarantine
            )

    field_map = load_field_map(str(resolve_field_map()))
    source_keys = {key for keys in field_map.values() for key in keys}
    reasons: dict[str, int] = {}
    held: dict[str, list[bytes]] = {}
    unknown: set[int] = set()
    events: list[Event] = []

    for line_no, raw_line in enumerate(raw.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            record = orjson.loads(raw_line)
        except orjson.JSONDecodeError:
            _bump(reasons, "malformed_json")
            held.setdefault("malformed_json", []).append(raw_line)
            continue
        if isinstance(record, list):
            _bump(reasons, "json_array")
            held.setdefault("json_array", []).append(raw_line)
            continue
        if not isinstance(record, dict):
            _bump(reasons, "malformed_json")
            held.setdefault("malformed_json", []).append(raw_line)
            continue

        reason, unknown_id = _skip_reason(
            record, source_keys=source_keys, field_map=field_map
        )
        if reason:
            _bump(reasons, reason)
            held.setdefault(reason, []).append(raw_line)
            if unknown_id is not None:
                unknown.add(unknown_id)
            continue

        cleaned, truncated = _truncate_record(record)
        if truncated:
            _bump(reasons, "huge_field")
            held.setdefault("huge_field", []).append(raw_line)
        event = event_from_record(
            cleaned,
            source_file=source_name,
            line_no=line_no,
            field_map=field_map,
        )
        if event is None:
            _bump(reasons, "missing_fields")
            held.setdefault("missing_fields", []).append(raw_line)
            continue
        if truncated:
            event.truncated = True
        events.append(event)

    paths = [
        path_str
        for reason, blobs in held.items()
        if (path_str := _write_quarantine(quarantine_root, source_name, reason, blobs))
    ]
    status = (
        "known_pattern"
        if any(matches_known_pattern(event) for event in events)
        else "insufficient_evidence"
    )
    skipped = sum(count for reason, count in reasons.items() if reason not in _KEPT_WITH_FLAG)
    report = IngestReport(
        parsed=len(events),
        skipped_by_reason=reasons,
        quarantined_path=paths,
        unknown_event_ids=sorted(unknown),
        status=status,
        source_file=source_name,
        skipped=skipped,
    )
    frame = pd.DataFrame([event_to_row(event) for event in events], columns=COLUMNS)
    return frame, report


def _log_paths(directory: str | Path) -> list[Path]:
    root = Path(directory)
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    return [
        path
        for path in sorted(root.iterdir())
        if path.is_file() and path.suffix.lower() in {".json", ".jsonl"}
    ]


def load_dir(directory: str | Path = "data/otrf") -> pd.DataFrame:
    """Read every .json and .jsonl file in directory through OtrfSysmonAdapter."""
    rows: list[dict[str, object]] = []
    adapter = OtrfSysmonAdapter()
    for path in _log_paths(directory):
        events, _report = adapter.to_events(path)
        rows.extend(event_to_row(event) for event in events)
    return pd.DataFrame(rows, columns=COLUMNS)


def load_events(directory: str | Path = "data/otrf") -> pd.DataFrame:
    """Normalized rows plus the original record. Accepts a directory or one file."""
    rows: list[dict[str, object]] = []
    adapter = OtrfSysmonAdapter()
    for path in _log_paths(directory):
        events, _report = adapter.to_events(path)
        for event in events:
            row = event_to_row(event)
            row["raw"] = event.raw
            rows.append(row)
    columns = [*COLUMNS, "raw"]
    return pd.DataFrame(rows, columns=columns)
