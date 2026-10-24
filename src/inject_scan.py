"""Heuristic scan for instruction-like text in attacker-controlled fields.

A hit is not a verdict. It marks a row for the titan arm to treat carefully.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel

# CommandLine/cmdline, TargetFilename/target_filename, ServiceName,
# ServiceFileName/service_path, Message. Normalized ingest columns are aliases.
ATTACKER_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("CommandLine", ("CommandLine", "cmdline", "process_command_line")),
    ("TargetFilename", ("TargetFilename", "target_filename", "file_path")),
    ("ServiceName", ("ServiceName", "service_name")),
    ("ServiceFileName", ("ServiceFileName", "service_path")),
    ("Message", ("Message", "message")),
)

# Labels are the spec strings. Matching is case-insensitive.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore previous", re.compile(r"ignore previous", re.IGNORECASE)),
    ("system:", re.compile(r"system:", re.IGNORECASE)),
    ("analista", re.compile(r"analista", re.IGNORECASE)),
    ("autorizado", re.compile(r"autorizado", re.IGNORECASE)),
    ("pentest", re.compile(r"pentest", re.IGNORECASE)),
    ("false positive", re.compile(r"false positive", re.IGNORECASE)),
    ("severity_override", re.compile(r"severity_override", re.IGNORECASE)),
    ("cerrar como benigno", re.compile(r"cerrar como benigno", re.IGNORECASE)),
    ("mark as benign", re.compile(r"mark as benign", re.IGNORECASE)),
    ("whitelisted", re.compile(r"whitelisted", re.IGNORECASE)),
    ("<!-- SOC_POLICY", re.compile(r"<!--\s*SOC_POLICY", re.IGNORECASE)),
    ("INICIO_INSTRUCCION", re.compile(r"INICIO_INSTRUCCION", re.IGNORECASE)),
    (
        "JSON decision close",
        re.compile(r"""['"]decision['"]\s*:\s*['"]close['"]""", re.IGNORECASE),
    ),
)

_SNIPPET = 180
_PAD = 40


class InjectionFinding(BaseModel):
    """One heuristic match in one attacker-controlled field."""

    row_id: str
    field: str
    matched_pattern: str
    snippet: str
    simulated_flag: bool = False


def scan_events(df: Any) -> list[InjectionFinding]:
    """Scan attacker-controlled fields. One finding per pattern hit."""
    findings: list[InjectionFinding] = []
    for row in _rows(df):
        simulated = _simulated(row)
        row_id = _text(_pick(row, "row_id"))
        for field, aliases in ATTACKER_FIELDS:
            text = _field_text(row, aliases)
            if not text:
                continue
            findings.extend(_hits(row_id, field, text, simulated))
    return findings


def _hits(row_id: str, field: str, text: str, simulated: bool) -> list[InjectionFinding]:
    found: list[InjectionFinding] = []
    for label, pattern in _PATTERNS:
        match = pattern.search(text)
        if match is None:
            continue
        found.append(
            InjectionFinding(
                row_id=row_id,
                field=field,
                matched_pattern=label,
                snippet=_snippet(text, match.start()),
                simulated_flag=simulated,
            )
        )
    return found


def _snippet(text: str, start: int) -> str:
    left = max(0, start - _PAD)
    return text[left : left + _SNIPPET]


def _field_text(row: Any, aliases: tuple[str, ...]) -> str:
    for key in aliases:
        text = _text(_pick(row, key))
        if text:
            return text
    raw = _pick(row, "raw")
    if isinstance(raw, Mapping):
        for key in aliases:
            text = _text(raw.get(key))
            if text:
                return text
    return ""


def _simulated(row: Any) -> bool:
    for key in ("simulated_flag", "simulated"):
        value = _pick(row, key)
        if not _missing(value):
            return _as_bool(value)
    raw = _pick(row, "raw")
    if isinstance(raw, Mapping):
        for key in ("simulated_flag", "simulated"):
            if key in raw and not _missing(raw.get(key)):
                return _as_bool(raw.get(key))
    return False


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    text = str(value).strip().casefold()
    return text in {"1", "true", "yes", "y"}


def _rows(df: Any) -> Iterable[Any]:
    if hasattr(df, "to_dict"):
        return df.to_dict("records")
    return df


def _pick(row: Any, key: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(key)
    return getattr(row, key, None)


def _missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    return type(value).__name__ == "NAType"


def _text(value: Any) -> str:
    if _missing(value):
        return ""
    text = str(value).strip()
    if text in {"-", "None", "<NA>"}:
        return ""
    return text
