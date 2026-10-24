"""Pure presentation helpers for the Titan.Log analyst console.

No Streamlit and no model calls: every value here is derived from the saved
cache, the Oracle, or the real OTRF rows. The app only renders the result.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

NOT_IN_CACHE = "[not in cache]"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INSUFFICIENT": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
    "INSUFFICIENT": "#94a3b8",
}
VERDICT_COLORS = {
    "VERIFIED": "#22c55e",
    "REFUTED": "#ef4444",
    "INSUFFICIENT": "#eab308",
}
_VERDICT_LABELS = {
    "VERIFIED": "VERIFIED",
    "REJECTED": "REFUTED",
    "UNVERIFIABLE": "INSUFFICIENT",
}

DETECTOR_LABELS = {
    "lsass_comsvcs": "LSASS dump via comsvcs.dll",
    "lsass_access_high": "LSASS access (high privilege)",
    "encoded_powershell": "Encoded PowerShell",
    "service_updater": "Service 'Updater' installed",
}
DETECTOR_SEVERITY = {
    "lsass_comsvcs": "CRITICAL",
    "lsass_access_high": "CRITICAL",
    "service_updater": "HIGH",
    "encoded_powershell": "HIGH",
}
DETECTOR_TECHNIQUE = {
    "lsass_comsvcs": ("T1003.001", "LSASS memory dump via comsvcs.dll MiniDump"),
    "lsass_access_high": ("T1003.001", "LSASS opened with dangerous granted access"),
    "encoded_powershell": ("T1059.001", "Encoded PowerShell execution"),
    "service_updater": ("T1569.002", "Service execution through a malicious service"),
}
PSEXEC_TECHNIQUE = ("T1021.002", "PsExec service execution / lateral movement")

# Analyst-time estimate. These are config defaults, not measured values.
MANUAL_MINUTES = (30, 45)
TITAN_MINUTES = (1, 3)


def _get(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and math.isnan(value):
        return ""
    text = str(value).strip()
    if text.casefold() in {"", "-", "none", "nan", "<na>"}:
        return ""
    return text


def _code_text(value: Any) -> str:
    text = _text(value)
    return text or "—"


def _ratio(closed: int | None, trials: int | None) -> str:
    if closed is None or trials is None:
        return "n/a"
    return f"{closed}/{trials}"


def _pct(closed: int, trials: int) -> str:
    if trials <= 0:
        return "0%"
    return f"{100 * closed / trials:.0f}%"


def severity_for_detector(detector: str) -> str:
    """Deterministic alert severity. Not an LLM verdict."""
    return DETECTOR_SEVERITY.get(detector, "MEDIUM")


def detector_label(detector: str) -> str:
    return DETECTOR_LABELS.get(detector, detector or "unknown detector")


def severity_style(value: str) -> str:
    color = SEVERITY_COLORS.get(str(value or "").upper(), "#94a3b8")
    return f"color: {color}; font-weight: 700;"


def verdict_style(value: str) -> str:
    color = VERDICT_COLORS.get(str(value or "").upper(), "#94a3b8")
    return f"color: {color}; font-weight: 700;"


def alert_rows(alerts: Iterable[Any]) -> list[dict[str, Any]]:
    """Queue rows sorted by deterministic severity, then time."""
    rows: list[dict[str, Any]] = []
    for alert in alerts:
        detector = _text(_get(alert, "detector"))
        ts = _text(_get(alert, "ts")) or "—"
        severity = severity_for_detector(detector)
        technique = DETECTOR_TECHNIQUE.get(detector)
        evidence = _text(_get(alert, "evidence")) or "—"
        if len(evidence) > 120:
            evidence = evidence[:119] + "…"
        rows.append(
            {
                "Severity": severity,
                "Alert": detector_label(detector),
                "Technique": technique[0] if technique else "—",
                "Host": _text(_get(alert, "host")) or "—",
                "User": _text(_get(alert, "user")) or "—",
                "Event ID": _get(alert, "event_code") or "—",
                "Time": ts,
                "Evidence": evidence,
                "_detector": detector,
                "_row_id": _text(_get(alert, "row_id")),
                "_sort": (SEVERITY_ORDER.get(severity, 9), ts),
            }
        )
    rows.sort(key=lambda row: row["_sort"])
    return rows


def verified_alert_ids(
    alerts: Iterable[Any],
    claims: Sequence[Any],
    verdicts: Sequence[Any],
) -> set[str]:
    """Alert row ids covered by at least one VERIFIED evidence claim."""
    by_id = {
        _text(_get(verdict, "claim_id")): _text(_get(verdict, "status"))
        for verdict in verdicts
    }
    verified_rows: set[str] = set()
    for claim in claims:
        if _text(_get(claim, "claim_type")) == "authorization":
            continue
        if by_id.get(_text(_get(claim, "claim_id"))) == "VERIFIED":
            row_id = _text(_get(claim, "row_id"))
            if row_id:
                verified_rows.add(row_id)
    return {
        _text(_get(alert, "row_id"))
        for alert in alerts
        if _text(_get(alert, "row_id")) in verified_rows
    }


def auto_resolved(
    alerts: Sequence[Any],
    claims: Sequence[Any],
    verdicts: Sequence[Any],
) -> dict[str, Any]:
    """Count alerts, not unique rows: two detectors can cite the same event."""
    verified_rows = verified_alert_ids(alerts, claims, verdicts)
    total = len(alerts)
    count = sum(1 for alert in alerts if _text(_get(alert, "row_id")) in verified_rows)
    return {"count": count, "total": total, "pct": _pct(count, total)}


def verdict_counts(verdicts: Sequence[Any]) -> dict[str, int]:
    counts = {"VERIFIED": 0, "REFUTED": 0, "INSUFFICIENT": 0}
    for verdict in verdicts:
        label = _VERDICT_LABELS.get(_text(_get(verdict, "status")), "INSUFFICIENT")
        counts[label] = counts.get(label, 0) + 1
    return counts


def escalation(gate: Mapping[str, Any] | None, verdicts: Sequence[Any], *, incidents: int) -> dict[str, Any]:
    """Escalated incidents with the reasons that forced human review."""
    gate = gate or {}
    level = _text(gate.get("level")).upper()
    counts = verdict_counts(verdicts)
    reasons: dict[str, int] = {}
    if level == "APPROVE":
        reasons["APPROVE gate"] = incidents
    if counts["REFUTED"]:
        reasons["REFUTED claim"] = incidents
    if counts["INSUFFICIENT"]:
        reasons["INSUFFICIENT evidence"] = incidents
    if not reasons and incidents:
        reasons["Human review"] = incidents
    return {
        "count": incidents,
        "level": level or NOT_IN_CACHE,
        "reasons": reasons,
        "refuted": counts["REFUTED"],
        "insufficient": counts["INSUFFICIENT"],
    }


def time_saved(
    *,
    manual: tuple[int, int] = MANUAL_MINUTES,
    titan: tuple[int, int] = TITAN_MINUTES,
    incidents: int = 1,
) -> dict[str, Any]:
    """Manual minus Titan minutes. An estimate from config defaults."""
    manual_mid = (manual[0] + manual[1]) / 2
    titan_mid = (titan[0] + titan[1]) / 2
    saved = manual_mid - titan_mid
    low = manual[0] - titan[1]
    high = manual[1] - titan[0]
    return {
        "per_incident": saved,
        "low": low,
        "high": high,
        "total": saved * incidents,
        "incidents": incidents,
        "manual": manual,
        "titan": titan,
    }


def analyst_minutes_estimate(
    *,
    manual: tuple[int, int] = MANUAL_MINUTES,
    titan: tuple[int, int] = TITAN_MINUTES,
) -> str:
    """The config ESTIMATE the UI shows. The tilde covers a non-integer midpoint."""
    saved = time_saved(manual=manual, titan=titan, incidents=1)
    midpoint = saved["per_incident"]
    shown = int(midpoint)
    tilde = "~" if midpoint != shown else ""
    return (
        f"{tilde}{shown} min saved per incident "
        f"(ESTIMATE: {saved['low']}–{saved['high']} min; "
        f"manual {manual[0]}–{manual[1]} min vs {titan[0]}–{titan[1]} min with Titan.Log; "
        f"assumptions, not measured)"
    )


def ops_kpis(
    event_counts: Mapping[str, Any] | None,
    alerts: Sequence[Any],
    claims: Sequence[Any],
    verdicts: Sequence[Any],
    gate: Mapping[str, Any] | None,
) -> dict[str, Any]:
    counts = event_counts or {}
    events = int(counts.get("events") or 0)
    alert_count = int(counts.get("alerts") or len(alerts))
    incidents = int(counts.get("incidents") or (1 if alerts else 0))
    resolved = auto_resolved(alerts, claims, verdicts)
    escalated = escalation(gate, verdicts, incidents=incidents)
    saved = time_saved(incidents=incidents)
    return {
        "events": events,
        "alerts": alert_count,
        "incidents": incidents,
        "auto": resolved,
        "escalated": escalated,
        "compression": {
            "events": events,
            "alerts": alert_count,
            "incidents": incidents,
            "events_per_incident": events / incidents if incidents else 0,
            "alerts_per_incident": alert_count / incidents if incidents else 0,
        },
        "time_saved": saved,
    }


def attack_techniques(view: Mapping[str, Any] | None, alerts: Sequence[Any]) -> list[dict[str, str]]:
    """Techniques from the LLM claims, else mapped by the detectors. Never an empty label."""
    view = view or {}
    findings: list[dict[str, str]] = []
    for technique in view.get("techniques") or []:
        technique_id = _text(_get(technique, "technique_id")) or "unknown"
        if any(item["technique_id"] == technique_id for item in findings):
            continue
        findings.append(
            {
                "technique_id": technique_id,
                "statement": _text(_get(technique, "statement")),
                "source": "LLM claim",
            }
        )
    if findings:
        return findings
    seen: set[str] = set()
    for alert in alerts:
        detector = _text(_get(alert, "detector"))
        mapped = DETECTOR_TECHNIQUE.get(detector)
        if mapped is None:
            continue
        technique_id, statement = mapped
        if technique_id not in seen:
            findings.append(
                {"technique_id": technique_id, "statement": statement, "source": "mapped by detector"}
            )
            seen.add(technique_id)
        source_file = _text(_get(alert, "source_file")).casefold()
        if detector == "service_updater" and "psexec" in source_file:
            psexec_id, psexec_statement = PSEXEC_TECHNIQUE
            if psexec_id not in seen:
                findings.append(
                    {
                        "technique_id": psexec_id,
                        "statement": psexec_statement,
                        "source": "mapped by detector",
                    }
                )
                seen.add(psexec_id)
    return findings


def timeline_rows(
    alerts: Iterable[Any],
    rows_by_id: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Chronological alert timeline with the detector-mapped technique."""
    rows_by_id = rows_by_id or {}
    timeline: list[dict[str, Any]] = []
    for alert in alerts:
        detector = _text(_get(alert, "detector"))
        row_id = _text(_get(alert, "row_id"))
        row = rows_by_id.get(row_id) or {}
        technique = DETECTOR_TECHNIQUE.get(detector)
        timeline.append(
            {
                "Time": _text(_get(alert, "ts")) or "—",
                "Host": _text(_get(alert, "host")) or _text(row.get("host_name")) or "—",
                "Process": _text(row.get("process_executable")) or "—",
                "Event ID": _get(alert, "event_code") or "—",
                "Technique": technique[0] if technique else "—",
                "Detector": detector_label(detector),
            }
        )
    timeline.sort(key=lambda item: item["Time"])
    return timeline


def claim_rows(claims: Sequence[Any], verdicts: Sequence[Any]) -> list[dict[str, Any]]:
    by_id = {
        _text(_get(verdict, "claim_id")): _get(verdict, "status")
        for verdict in verdicts
    }
    reasons = {
        _text(_get(verdict, "claim_id")): _text(_get(verdict, "reason"))
        for verdict in verdicts
    }
    rows: list[dict[str, Any]] = []
    for claim in claims:
        claim_id = _text(_get(claim, "claim_id"))
        status = _text(by_id.get(claim_id))
        rows.append(
            {
                "Claim ID": claim_id,
                "Type": _text(_get(claim, "claim_type")) or "—",
                "Claim": _text(_get(claim, "statement")) or "—",
                "Host": _text(_get(claim, "host")) or "—",
                "User": _text(_get(claim, "user")) or "—",
                "Technique": _text(_get(claim, "technique_id")) or "—",
                "Verdict": _VERDICT_LABELS.get(status, "INSUFFICIENT"),
                "Evidence row id": _text(_get(claim, "row_id")) or "—",
                "Oracle reason": reasons.get(claim_id, "—") or "—",
            }
        )
    return rows


def escalation_packet(
    view: Mapping[str, Any],
    *,
    incident: Mapping[str, Any] | None = None,
) -> str:
    """Copyable plain-text packet: every claim, verdict, row id, and the gate."""
    incident = incident or {}
    lines = ["TITAN.LOG // ESCALATION PACKET", "=" * 40]
    if incident:
        lines.append(
            "Incident: severity={severity} close={close} hosts={hosts} window={start} to {end}".format(
                severity=incident.get("severity") or NOT_IN_CACHE,
                close=incident.get("close") if incident.get("close") is not None else NOT_IN_CACHE,
                hosts=", ".join(str(item) for item in incident.get("hosts") or []) or "—",
                start=incident.get("window_start") or "—",
                end=incident.get("window_end") or "—",
            )
        )
    lines.append(f"Gate: {view.get('gate') or NOT_IN_CACHE}")
    lines.append("")
    lines.append("CLAIMS AND ORACLE VERDICTS")
    for row in view.get("rows") or []:
        lines.append(
            f"[{row.get('Verdict') or 'INSUFFICIENT':<11}] "
            f"{row.get('Claim') or ''}  (row {row.get('Evidence row id') or '—'})"
        )
    rejected = view.get("rejected") or []
    if rejected:
        lines.append("")
        lines.append("REJECTED BY THE ORACLE")
        for item in rejected:
            lines.append(
                f"[{item.get('claim_id') or '—'}] {item.get('statement') or ''}\n"
                f"  reason: {item.get('reason') or NOT_IN_CACHE}"
            )
    evidence = view.get("evidence_claim_ids") or []
    lines.append("")
    lines.append(f"EVIDENCE CLAIM IDS: {', '.join(evidence) if evidence else '—'}")
    lines.append("NO LIVE MODEL CALL. VALUES READ FROM THE SAVED RUN.")
    return "\n".join(lines)


def model_arm_rows(summary: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Model x arm table. Titan.Log rows are flagged for highlighting."""
    rows: list[dict[str, Any]] = []
    for row in (summary or {}).get("rows") or []:
        arm = _text(row.get("arm")) or "unknown"
        rows.append(
            {
                "Model": _text(row.get("model_id")) or "unknown",
                "Arm": "Titan.Log" if arm == "titan" else arm,
                "AFCR n=10": f"{_ratio(row.get('afcr_closed'), row.get('afcr_trials'))} "
                f"({_pct(int(row.get('afcr_closed') or 0), int(row.get('afcr_trials') or 0))})",
                "I01–I04": f"{_ratio(row.get('afcr_i01_i04_closed'), row.get('afcr_i01_i04_trials'))} "
                f"({_pct(int(row.get('afcr_i01_i04_closed') or 0), int(row.get('afcr_i01_i04_trials') or 0))})",
                "Any close n=18": f"{_ratio(row.get('any_close_all_18_closed'), row.get('any_close_all_18_trials'))} "
                f"({_pct(int(row.get('any_close_all_18_closed') or 0), int(row.get('any_close_all_18_trials') or 0))})",
                "Influence n=18": f"{_ratio(row.get('influenced'), row.get('influence_trials'))} "
                f"({_pct(int(row.get('influenced') or 0), int(row.get('influence_trials') or 0))})",
                "_titan": arm == "titan",
            }
        )
    return rows


def cached(value: Any) -> str:
    """A cache field as text, or the explicit missing marker. Never a guess."""
    if value is None:
        return NOT_IN_CACHE
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip()
    return text or NOT_IN_CACHE


def first_sentences(text: Any, count: int = 2) -> str:
    """A short quote for the side-by-side. The full text stays in an expander."""
    body = _text(text)
    if not body:
        return NOT_IN_CACHE
    import re

    parts = re.split(r"(?<=[.!?])\s+", body)
    return " ".join(parts[:count]) or body


def compact_row(row: Mapping[str, Any]) -> str:
    """One log line for the evidence and injection panes."""
    ts = _text(row.get("ts")) or _text(row.get("UtcTime")) or "—"
    host = _text(row.get("host_name")) or _text(row.get("Hostname")) or "—"
    user = _text(row.get("user_name")) or _text(row.get("User")) or "—"
    code = _get(row, "event_code")
    if code is None:
        code = row.get("EventID")
    code_text = _code_text(code)
    process = (
        _text(row.get("process_executable"))
        or _text(row.get("Image"))
        or _text(row.get("NewProcessName"))
        or "—"
    )
    command = _text(row.get("process_command_line")) or _text(row.get("CommandLine")) or ""
    raw = row.get("raw") if isinstance(row.get("raw"), Mapping) else {}
    service = _text(row.get("service_name")) or _text(raw.get("ServiceName"))
    file_path = _text(row.get("file_path")) or _text(raw.get("TargetFilename"))
    message = _text(raw.get("Message")) or _text(row.get("Message"))
    command = " ".join(command.split())
    service = " ".join(service.split())
    file_path = " ".join(file_path.split())
    message = " ".join(message.split())
    line = f"{ts}  {host}  {user}  E{code_text}  {process}  {command}"
    if service:
        line += f"  service={service}"
    if file_path:
        line += f"  file={file_path}"
    if message:
        line += f"  message={message[:180]}"
    return line


def row_badges(row: Mapping[str, Any]) -> dict[str, str]:
    """Key fields for the badge strip above a raw event."""
    raw = row.get("raw") if isinstance(row.get("raw"), Mapping) else {}
    merged = {**raw, **row}

    def pick(*keys: str) -> str:
        for key in keys:
            value = merged.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if text.casefold() not in {"", "-", "none", "nan", "<na>"}:
                return text
        return "—"

    return {
        "timestamp": pick("ts", "UtcTime", "TimeCreated"),
        "host": pick("host_name", "Hostname", "host"),
        "user": pick("user_name", "User", "user"),
        "event_id": pick("event_code", "EventID"),
        "image": pick("process_executable", "Image", "NewProcessName"),
        "command_line": pick("process_command_line", "CommandLine"),
        "target": pick("target_process_executable", "TargetImage"),
        "parent": pick("process_parent_executable", "ParentImage"),
    }
