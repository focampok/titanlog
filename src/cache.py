"""Offline run cache. The public demo reads this file and does not call a model.

save_run() writes results/run_cache.json. The version string is the package
version, not a git revision. The AFCR summary and AFCR table are copied from
their saved files when those files exist.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from correlate import Incident

VERSION = "0.1.0"
_REPO = Path(__file__).resolve().parents[1]
SUMMARY_PATH = _REPO / "results" / "afcr_summary.json"
TABLE_PATH = _REPO / "results" / "afcr_table.json"
CACHE_PATH = _REPO / "results" / "run_cache.json"

_EMPTY: dict[str, Any] = {
    "model": "",
    "event_counts": {},
    "alerts": [],
    "incident": None,
    "claims": [],
    "verdicts": [],
    "afcr_table": None,
    "afcr_summary": None,
    "gate": None,
}


def load_afcr_summary(path: str | Path | None = None) -> dict[str, Any] | None:
    """Return the saved summary, or None when the file is absent."""
    return _load_object(Path(path) if path is not None else SUMMARY_PATH)


def payload_from_incident(incident: Incident) -> dict[str, Any]:
    """Serialize one finished triage for save_run(). Counts come from the incident."""
    compression = incident.compression
    return {
        "model": incident.model_id or "",
        "event_counts": {
            "events": compression.events,
            "alerts": compression.alerts,
            "incidents": compression.incidents,
        },
        "alerts": [alert.model_dump(mode="json") for alert in incident.alerts],
        "incident": incident.model_dump(mode="json"),
        "claims": [claim.model_dump(mode="json") for claim in incident.claims],
        "verdicts": [verdict.model_dump(mode="json") for verdict in incident.verdicts],
        "gate": incident.gate.model_dump(mode="json") if incident.gate else None,
    }


def save_run(
    payload: dict[str, Any],
    *,
    cache_path: str | Path | None = None,
    summary_path: str | Path | None = None,
    table_path: str | Path | None = None,
) -> Path:
    """Write results/run_cache.json, including the saved AFCR summary and table."""
    target = Path(cache_path) if cache_path is not None else CACHE_PATH
    now = datetime.now(UTC).isoformat()
    body = dict(_EMPTY)
    body.update(payload)
    body["version"] = VERSION
    body["saved_at"] = now
    timestamps = dict(body.get("timestamps") or {})
    timestamps["saved_at"] = now
    body["timestamps"] = timestamps
    summary = load_afcr_summary(summary_path)
    if summary is not None:
        body["afcr_summary"] = summary
    table = _load_object(Path(table_path) if table_path is not None else TABLE_PATH)
    if table is not None:
        body["afcr_table"] = table
    if not body.get("model"):
        body["model"] = _recorded_model(body)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return target


def load_run(path: str | Path | None = None) -> dict[str, Any]:
    """Read the offline cache."""
    target = Path(path) if path is not None else CACHE_PATH
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("run cache must be a JSON object")
    return data


def _recorded_model(body: dict[str, Any]) -> str:
    """Model ids already stored on the summary or the AFCR table. No provider call."""
    found: list[str] = []
    summary = body.get("afcr_summary") or {}
    rows = summary.get("rows") if isinstance(summary, dict) else None
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        model_id = str(row.get("model_id") or "")
        if model_id and model_id not in found:
            found.append(model_id)
    if found:
        return ", ".join(found)
    table = body.get("afcr_table")
    if isinstance(table, dict):
        return str(table.get("model_id") or "")
    return ""


def _load_object(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    return data
