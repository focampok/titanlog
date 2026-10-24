"""P0 detectors. Each function is pure and returns alerts, not a verdict."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from pydantic import BaseModel

_ENC = re.compile(r"(?:^|[^a-z0-9])-enc(?:odedcommand)?(?:[^a-z0-9]|$)")
_B64 = re.compile(r"frombase64string")
_VM_READ = 0x10
_QUERY_LIMITED = 0x1000
_EVIDENCE_LIMIT = 180


class Alert(BaseModel):
    """One detector hit on one row."""

    detector: str
    row_id: str
    event_code: int
    host: str | None = None
    user: str | None = None
    ts: str | None = None
    evidence: str
    source_file: str = ""


class _View(BaseModel):
    row_id: str
    event_code: int
    command_line: str = ""
    service_path: str = ""
    target_image: str = ""
    granted_access: str = ""
    service_name: str = ""
    host: str | None = None
    user: str | None = None
    ts: str | None = None
    source_file: str = ""


def dangerous_access(value: str | None) -> bool:
    """PROCESS_VM_READ together with PROCESS_QUERY_LIMITED_INFORMATION."""
    if not value:
        return False
    text = value.strip().casefold()
    try:
        mask = int(text, 16) if text.startswith("0x") else int(text, 10)
    except ValueError:
        return False
    needed = _VM_READ | _QUERY_LIMITED
    return (mask & needed) == needed


def _missing(value: Any) -> bool:
    return value is None or (isinstance(value, float) and math.isnan(value))


def _text(value: Any) -> str:
    if _missing(value):
        return ""
    text = str(value).strip()
    if text in {"-", "None"}:
        return ""
    return text


def _ts_text(value: Any) -> str | None:
    if _missing(value):
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    text = str(value).strip()
    return text or None


def _pick(row: Any, key: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(key)
    return getattr(row, key, None)


def _view(row: Any) -> _View | None:
    code = _pick(row, "event_code")
    if _missing(code):
        return None
    try:
        event_code = int(code)
    except (TypeError, ValueError):
        return None
    host = _text(_pick(row, "host_key")) or _text(_pick(row, "host_name")) or None
    user = _text(_pick(row, "user_name")) or None
    return _View(
        row_id=_text(_pick(row, "row_id")),
        event_code=event_code,
        command_line=_text(_pick(row, "process_command_line")),
        service_path=_text(_pick(row, "service_path")),
        target_image=_text(_pick(row, "target_process_executable")),
        granted_access=_text(_pick(row, "granted_access")),
        service_name=_text(_pick(row, "service_name")),
        host=host,
        user=user,
        ts=_ts_text(_pick(row, "ts")),
        source_file=_text(_pick(row, "source_file")),
    )


def _snippet(text: str, needle: str) -> str:
    folded = text.casefold()
    at = folded.find(needle.casefold())
    if at < 0:
        return text[:_EVIDENCE_LIMIT]
    start = max(0, at - 40)
    return text[start : start + _EVIDENCE_LIMIT]


def _alert(view: _View, detector: str, evidence: str) -> Alert:
    return Alert(
        detector=detector,
        row_id=view.row_id,
        event_code=view.event_code,
        host=view.host,
        user=view.user,
        ts=view.ts,
        evidence=evidence,
        source_file=view.source_file,
    )


def lsass_comsvcs(view: _View) -> Alert | None:
    command = view.command_line.casefold()
    if view.event_code not in {1, 4688}:
        return None
    if "comsvcs.dll" not in command or "minidump" not in command:
        return None
    return _alert(view, "lsass_comsvcs", _snippet(view.command_line, "comsvcs.dll"))


def lsass_access_high(view: _View) -> Alert | None:
    if view.event_code != 10 or "lsass" not in view.target_image.casefold():
        return None
    if not dangerous_access(view.granted_access):
        return None
    evidence = f"{view.target_image} {view.granted_access}".strip()
    return _alert(view, "lsass_access_high", evidence[:_EVIDENCE_LIMIT])


def encoded_powershell(view: _View) -> Alert | None:
    text = f"{view.command_line}\n{view.service_path}"
    folded = text.casefold()
    if _B64.search(folded):
        needle = "frombase64string"
    elif _ENC.search(folded):
        needle = "-enc"
    else:
        return None
    return _alert(view, "encoded_powershell", _snippet(text, needle))


def service_updater(view: _View) -> Alert | None:
    if view.event_code not in {4697, 7045}:
        return None
    path = view.service_path.casefold()
    if view.service_name.casefold() != "updater" and "powershell" not in path:
        return None
    evidence = view.service_path or view.service_name
    return _alert(view, "service_updater", evidence[:_EVIDENCE_LIMIT])


_DETECTORS = (lsass_comsvcs, lsass_access_high, encoded_powershell, service_updater)


def detect(records: Iterable[Any]) -> list[Alert]:
    """Run the four P0 detectors. Schtask and lateral movement are not included."""
    rows: Iterable[Any]
    if hasattr(records, "to_dict"):
        rows = records.to_dict("records")
    else:
        rows = records
    alerts: list[Alert] = []
    for row in rows:
        view = _view(row)
        if view is None:
            continue
        for detector in _DETECTORS:
            alert = detector(view)
            if alert is not None:
                alerts.append(alert)
    return alerts
