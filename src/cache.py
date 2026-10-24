"""Offline run cache. The public demo reads this file and does not call a model.

save_run() writes results/run_cache.json. The version string is the package
version, not a git revision. The AFCR summary and AFCR table are copied from
their saved files when those files exist.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from correlate import Incident

VERSION = "0.1.0"
_REPO = Path(__file__).resolve().parents[1]
SUMMARY_PATH = _REPO / "results" / "afcr_summary.json"
TABLE_PATH = _REPO / "results" / "afcr_table.json"
CACHE_PATH = _REPO / "results" / "run_cache.json"
INJECTIONS_PATH = _REPO / "data" / "simulated" / "injections.jsonl"
# The Naive arm in the demo is Qwen3-30B. Prefer its saved trials.
_PARTIAL_PATHS = (
    _REPO / "results" / "afcr_partial_qwen30b.jsonl",
    _REPO / "results" / "afcr_partial_deepseek.jsonl",
)
_VARIANTS_TABLE_PATHS = (
    _REPO / "results" / "afcr_table_qwen30b.json",
    _REPO / "results" / "afcr_table.json",
)
_INJECTED_FIELDS = (
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
    "base_row_id",
    "simulated",
    "injection_id",
    "attack_objective",
)
_INJECTED_RAW_FIELDS = (
    "EventID",
    "UtcTime",
    "TimeCreated",
    "Channel",
    "Hostname",
    "User",
    "Image",
    "NewProcessName",
    "CommandLine",
    "ParentImage",
    "TargetImage",
    "GrantedAccess",
    "ServiceName",
    "ServiceFileName",
    "ImagePath",
    "TargetFilename",
    "Message",
)

_EMPTY: dict[str, Any] = {
    "model": "",
    "provider_host": "",
    "event_counts": {},
    "alerts": [],
    "incident": None,
    "claims": [],
    "verdicts": [],
    "afcr_table": None,
    "afcr_summary": None,
    "afcr_variants": None,
    "gate": None,
    "rationale": "",
}

_VERDICT_LABELS = {
    "VERIFIED": "VERIFIED",
    "REJECTED": "REFUTED",
    "UNVERIFIABLE": "INSUFFICIENT",
}


def load_afcr_summary(path: str | Path | None = None) -> dict[str, Any] | None:
    """Return the saved summary, or None when the file is absent."""
    return _load_object(Path(path) if path is not None else SUMMARY_PATH)


def load_cached_injections(
    *,
    partial_path: str | Path | None = None,
    table_path: str | Path | None = None,
    injections_path: str | Path | None = None,
) -> dict[str, Any] | None:
    """Saved injection decisions, rationales, and rows. No model call.

    The source is the partial JSONL written by the AFCR eval, the per-injection
    table, and the saved simulated variants. A missing field stays missing; the
    app renders "[not in cache]".
    """
    partial = _first_existing(Path(partial_path) if partial_path else None, _PARTIAL_PATHS)
    if partial is None:
        return None
    records = [
        row
        for row in _read_jsonl(partial)
        if str(row.get("injection_id") or "") not in {"", "__baseline__"}
    ]
    if not records:
        return None
    table = _load_object_from(
        Path(table_path) if table_path else None,
        _VARIANTS_TABLE_PATHS,
    ) or {}
    by_injection = table.get("by_injection") if isinstance(table.get("by_injection"), dict) else {}
    injected_rows = {
        str(row.get("injection_id") or ""): row
        for row in _read_jsonl(Path(injections_path) if injections_path else INJECTIONS_PATH)
        if str(row.get("injection_id") or "")
    }
    variants: dict[str, Any] = {}
    for record in records:
        injection_id = str(record.get("injection_id") or "")
        arm = str(record.get("arm") or "")
        if not injection_id or not arm:
            continue
        entry = variants.setdefault(
            injection_id,
            {
                "injection_id": injection_id,
                "attack_objective": str(record.get("attack_objective") or ""),
                "model_id": str(record.get("model_id") or ""),
                "provider_host": str(record.get("provider_host") or ""),
                "arms": {},
            },
        )
        trial = int(record.get("trial") or 1)
        previous = entry["arms"].get(arm)
        if previous is None or trial < int(previous.get("trial") or 999):
            entry["arms"][arm] = {
                "trial": trial,
                "timestamp": record.get("timestamp"),
                "model_id": record.get("model_id"),
                "provider_host": record.get("provider_host"),
                "outcome": record.get("outcome"),
                "severity": record.get("severity"),
                "close": record.get("close"),
                "rationale": record.get("rationale"),
                "fallback": record.get("fallback"),
                "tai": record.get("tai"),
                "rejected_authorization": record.get("rejected_authorization"),
            }
        entry["counts"] = by_injection.get(injection_id) or {}
        injected = injected_rows.get(injection_id)
        if injected is not None:
            entry["field"] = _injected_field(injection_id)
            entry["payload"] = _injection_payload(injection_id)
            entry["base_row_id"] = str(injected.get("base_row_id") or "")
            entry["injected_row"] = _trim_injected_row(injected)
    if not variants:
        return None
    first = records[0]
    return {
        "simulated": True,
        "model_id": str(table.get("model_id") or first.get("model_id") or ""),
        "provider_host": str(table.get("provider_host") or first.get("provider_host") or ""),
        "source": partial.name,
        "variants": dict(sorted(variants.items())),
    }


def _injection_payload(injection_id: str) -> str:
    from inject import injection_payload

    return injection_payload(injection_id)


def _injected_field(injection_id: str) -> str:
    from inject import _VARIANTS

    for spec in _VARIANTS:
        if spec[0] == injection_id:
            return spec[2]
    return ""


def _trim_injected_row(row: dict[str, Any]) -> dict[str, Any]:
    trimmed = {key: row.get(key) for key in _INJECTED_FIELDS if key in row}
    raw = row.get("raw")
    if isinstance(raw, dict):
        trimmed["raw"] = {
            key: raw.get(key) for key in _INJECTED_RAW_FIELDS if key in raw
        }
    return trimmed


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _first_existing(explicit: Path | None, candidates: tuple[Path, ...]) -> Path | None:
    if explicit is not None:
        return explicit if explicit.exists() else None
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _load_object_from(explicit: Path | None, candidates: tuple[Path, ...]) -> dict[str, Any] | None:
    target = _first_existing(explicit, candidates)
    return _load_object(target) if target is not None else None


def payload_from_incident(incident: Incident) -> dict[str, Any]:
    """Serialize one finished triage for save_run(). Counts come from the incident."""
    compression = incident.compression
    return {
        "model": incident.model_id or "",
        "provider_host": incident.base_url_host or "",
        "rationale": incident.rationale or "",
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


def investigation_view(source: Incident | Mapping[str, Any]) -> dict[str, Any]:
    """Claims table, verdict labels, and gate line for the live view and the cache view.

    Oracle status REJECTED is shown as REFUTED. UNVERIFIABLE is shown as INSUFFICIENT.
    """
    if isinstance(source, Incident):
        data: Mapping[str, Any] = payload_from_incident(source)
        incident = data.get("incident") or {}
    else:
        data = source
        incident = data.get("incident") if isinstance(data.get("incident"), dict) else {}
    claims = list(data.get("claims") or incident.get("claims") or [])
    verdicts = list(data.get("verdicts") or incident.get("verdicts") or [])
    gate = data.get("gate") if data.get("gate") is not None else incident.get("gate")
    rationale = str(data.get("rationale") or incident.get("rationale") or "")
    model = str(data.get("model") or incident.get("model_id") or "")
    provider_host = str(data.get("provider_host") or incident.get("base_url_host") or "")
    verdict_by_id = {
        str(item.get("claim_id")): item
        for item in (_mapping(verdict) for verdict in verdicts)
    }
    rows: list[dict[str, str]] = []
    narrative: list[str] = []
    techniques: list[dict[str, str]] = []
    evidence_ids: list[str] = []
    rejected: list[dict[str, str]] = []
    for claim in claims:
        item = _mapping(claim)
        statement = str(item.get("statement") or "")
        claim_type = str(item.get("claim_type") or "")
        claim_id = str(item.get("claim_id") or "")
        verdict = verdict_by_id.get(claim_id) or {}
        status = str(verdict.get("status") or "")
        if claim_type != "authorization" and claim_id and status != "REJECTED":
            evidence_ids.append(claim_id)
        if status == "REJECTED":
            rejected.append(
                {
                    "claim_id": claim_id,
                    "statement": statement,
                    "reason": str(verdict.get("reason") or ""),
                    "row_id": str(item.get("row_id") or ""),
                }
            )
        rows.append(
            {
                "Claim": statement,
                "Verdict": _VERDICT_LABELS.get(status, "INSUFFICIENT"),
                "Evidence row id": str(item.get("row_id") or ""),
            }
        )
        if claim_type == "attack_technique":
            techniques.append(
                {
                    "technique_id": str(item.get("technique_id") or "unknown"),
                    "statement": statement,
                }
            )
        elif statement:
            narrative.append(statement)
    gate_map = gate if isinstance(gate, dict) else {}
    level = str(gate_map.get("level") or "")
    reason = str(gate_map.get("reason") or "")
    return {
        "model": model,
        "provider_host": provider_host,
        "rationale": rationale,
        "narrative": narrative,
        "techniques": techniques,
        "rows": rows,
        "rejected": rejected,
        "evidence_claim_ids": evidence_ids,
        "gate_level": level,
        "gate_action": str(gate_map.get("action") or ""),
        "gate": f"Gate: {level}. {reason}" if level else "",
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
    variants = load_cached_injections()
    if variants is not None:
        body["afcr_variants"] = variants
    if not body.get("model"):
        body["model"] = _recorded_model(body)
    if not body.get("provider_host"):
        incident = body.get("incident") if isinstance(body.get("incident"), dict) else {}
        body["provider_host"] = str(incident.get("base_url_host") or "")
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


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json")
        if isinstance(dumped, dict):
            return dumped
    return {}


def _load_object(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    return data
