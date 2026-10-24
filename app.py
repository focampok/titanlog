"""Titan.Log event preview. Run from the repo root: streamlit run app.py."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cache import investigation_view, load_run, payload_from_incident, save_run
from correlate import GateRecommendation, correlate
from demo_forged import NOT_IN_CACHE, review_forged
from detectors import detect
from gate import execute, record_audit
from ingest import REASONS, ingest_file, load_dir
from titanlog import triage

DATA_DIR = ROOT / "data" / "otrf"

REASON_LABELS = {
    "malformed_json": "Malformed JSON",
    "missing_fields": "Missing fields",
    "unknown_event_id": "Unknown event ID",
    "empty_file": "Empty file",
    "huge_field": "Truncated field over 64 KB",
    "non_windows": "Not Windows or Sysmon JSON",
    "json_array": "JSON array instead of JSONL",
    "impossible_timestamp": "Impossible timestamp",
    "insufficient_evidence": "Insufficient evidence",
}

st.set_page_config(page_title="Titan.Log", layout="wide")
st.title("Titan.Log")
use_cache = st.sidebar.checkbox("Use cache (offline demo)", value=True)
st.sidebar.caption("Skips the model and loads the saved run.")
if st.sidebar.button("Load demo: forged incident"):
    st.session_state["forged_demo"] = review_forged()


def _show_forged(result) -> None:
    """Render the forged file. Oracle verdicts are computed here. Cache fields are copied or marked missing."""
    if os.environ.get("DEMO_READONLY") == "1":
        st.caption("Public demo — cached results; no live LLM")
    st.subheader("Forged incident")
    st.caption("SIMULATED")
    st.write(f"Quarantined: {result.quarantined}")
    if result.reasons:
        st.dataframe(
            [
                {"Reason": REASON_LABELS.get(reason, reason), "Count": count}
                for reason, count in result.reasons.items()
            ],
            hide_index=True,
        )
    if result.insufficient_lines:
        st.warning(
            f"Insufficient evidence: {result.insufficient_lines} line missing host, user, and EventID."
        )
    for line in result.injections:
        st.markdown(f"⚠ SIMULATED `{line}`")
    if result.incident_detected:
        st.write(f"Incident still detected. Alerts: {result.alert_count}.")
    else:
        st.write("Incident not detected.")
    for label, statement in result.injection_verdicts:
        st.write(f"{label}: {statement}")
    st.write(f"close={'true' if result.close else 'false'}")
    st.write(f"Cached close: {result.cache_close}")
    st.write(f"Cached claim: {result.cache_claim}")
    if result.cache_claim == NOT_IN_CACHE or result.cache_close == NOT_IN_CACHE:
        st.write(NOT_IN_CACHE)


forged = st.session_state.get("forged_demo")
if forged is not None:
    _show_forged(forged)


@st.cache_data(show_spinner=False)
def _load(directory: str) -> pd.DataFrame:
    return load_dir(directory)


def _show_report(frame: pd.DataFrame, report) -> None:
    counts = st.columns(2)
    counts[0].metric("Parsed", report.parsed)
    counts[1].metric("Skipped", report.skipped)
    if report.status == "insufficient_evidence":
        st.warning("Insufficient evidence — sent to human")
    elif report.status == "known_pattern":
        st.info("A known pattern is present. This screen does not assign a verdict.")

    reason_rows = [
        {"Reason": REASON_LABELS.get(reason, reason), "Count": report.skipped_by_reason[reason]}
        for reason in REASONS
        if reason in report.skipped_by_reason
    ]
    if reason_rows:
        st.dataframe(pd.DataFrame(reason_rows), hide_index=True)
    if report.unknown_event_ids:
        ids = ", ".join(str(event_id) for event_id in report.unknown_event_ids)
        st.write(f"Unknown event IDs: {ids}")
    if report.quarantined_path:
        st.write("Quarantine")
        for path in report.quarantined_path:
            st.code(path, language=None)
    if frame.empty:
        st.info("No events parsed from this file.")
    else:
        st.dataframe(frame.head(50))


frame = _load(str(DATA_DIR))
file_count = int(frame["source_file"].nunique()) if len(frame) else 0

counts = st.columns(2)
counts[0].metric("total_events", len(frame))
counts[1].metric("files", file_count)

def _ratio(closed: object, trials: object) -> str:
    if closed is None or trials is None:
        return "n/a"
    return f"{closed}/{trials}"


def _show_cached_run(cache: dict) -> None:
    st.subheader("Cached run")
    counts = cache.get("event_counts") or {}
    metrics = st.columns(3)
    metrics[0].metric("Events", int(counts.get("events") or 0))
    metrics[1].metric("Alerts", int(counts.get("alerts") or 0))
    metrics[2].metric("Incidents", int(counts.get("incidents") or 0))
    if cache.get("model"):
        st.caption(f"Model recorded in the cache: {cache['model']}")

    summary = cache.get("afcr_summary") or {}
    st.subheader("AFCR")
    if summary.get("simulated"):
        st.caption("SIMULATED")
    rows = summary.get("rows") or []
    if rows:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Model": row.get("model_id") or "",
                        "Arm": row.get("arm") or "",
                        "AFCR": _ratio(row.get("afcr_closed"), row.get("afcr_trials")),
                        "AFCR I01-I04": _ratio(
                            row.get("afcr_i01_i04_closed"),
                            row.get("afcr_i01_i04_trials"),
                        ),
                        "Any close": _ratio(
                            row.get("any_close_all_18_closed"),
                            row.get("any_close_all_18_trials"),
                        ),
                        "Influence": _ratio(row.get("influenced"), row.get("influence_trials")),
                    }
                    for row in rows
                ]
            ),
            hide_index=True,
        )
    else:
        st.info("The cache has no AFCR summary.")

    _show_investigation_view(investigation_view(cache))


def _show_investigation_view(view: dict, *, controls: bool = True) -> None:
    model = view.get("model") or ""
    host = view.get("provider_host") or ""
    if model or host:
        st.caption(f"Model: {model} ({host})" if host else f"Model: {model}")

    st.subheader("Narrative")
    narrative = view.get("narrative") or []
    if narrative:
        for statement in narrative:
            st.write(statement)
    elif view.get("rationale"):
        st.write(view["rationale"])
    else:
        st.info("No narrative was returned.")

    st.subheader("ATT&CK")
    techniques = view.get("techniques") or []
    if techniques:
        for technique in techniques:
            st.write(f"{technique.get('technique_id') or 'unknown'}: {technique.get('statement') or ''}")
    else:
        st.info("No ATT&CK technique was claimed.")

    st.subheader("Claims")
    rows = view.get("rows") or []
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True)
    else:
        st.info("No claims.")
    if view.get("gate"):
        st.write(view["gate"])
    _show_escalation_packet(view)
    if controls:
        _show_gate_controls(view)


def _show_escalation_packet(view: dict) -> None:
    """Rejected claims stay visible, with the Oracle reason, after they leave the action."""
    with st.expander("Escalation packet"):
        if view.get("gate"):
            st.write(view["gate"])
        rejected = view.get("rejected") or []
        if not rejected:
            st.write("No claims were rejected by the Oracle.")
            return
        st.write("Rejected by the Oracle")
        for item in rejected:
            claim_id = item.get("claim_id") or ""
            statement = item.get("statement") or ""
            st.write(f"{claim_id}: {statement}" if claim_id else statement)
            reason = item.get("reason") or ""
            if reason:
                st.caption(reason)


def _show_gate_controls(view: dict) -> None:
    level = view.get("gate_level") or ""
    action = view.get("gate_action") or ""
    evidence_ids = list(view.get("evidence_claim_ids") or [])
    if level == "AUTO" and action == "disable_account":
        token = "AUTO:" + ",".join(evidence_ids)
        if st.session_state.get("gate_auto") != token:
            execute(
                _decision(level, action),
                actor="titan",
                evidence_ids=evidence_ids,
            )
            st.session_state["gate_auto"] = token
        st.info("AUTO: the mock disable_account action was recorded.")
        return
    if level != "APPROVE" or action != "disable_account":
        return
    st.write("Approve or deny disable_account.")
    approve, deny = st.columns(2)
    decision = _decision(level, action)
    if approve.button("Approve"):
        execute(decision, actor="analyst", evidence_ids=evidence_ids)
        st.success("Approved. The mock disable_account action was recorded.")
    if deny.button("Deny"):
        record_audit(
            actor="analyst",
            action="disable_account",
            evidence_ids=evidence_ids,
            gate_decision="DENY",
            executed=False,
        )
        st.warning("Denied. No action was executed.")


def _decision(level: str, action: str) -> GateRecommendation:
    return GateRecommendation(level=level, action=action, reason="")


def _show_investigation(result) -> None:
    _show_investigation_view(investigation_view(result))


if use_cache:
    try:
        _show_cached_run(load_run())
    except (OSError, ValueError, TypeError):
        st.error("No offline cache was found.")

if st.button("Detect"):
    alerts = detect(frame)
    st.session_state["incident"] = correlate(frame, alerts)
    st.session_state.pop("investigation", None)

incident = st.session_state.get("incident")
if incident is not None:
    compression = incident.compression
    st.markdown(compression.label())
    hosts = ", ".join(incident.hosts) if incident.hosts else "none"
    users = ", ".join(incident.users) if incident.users else "none"
    st.write(f"Hosts: {hosts}")
    st.write(f"Users: {users}")
    if incident.window_start and incident.window_end:
        st.write(f"Window: {incident.window_start} to {incident.window_end}")
    if incident.alerts:
        st.dataframe(
            [
                {
                    "detector": alert.detector,
                    "host": alert.host,
                    "user": alert.user,
                    "event_code": alert.event_code,
                    "evidence": alert.evidence,
                }
                for alert in incident.alerts
            ]
        )
    else:
        st.info("No alerts.")

    if use_cache:
        if st.button("Investigate"):
            st.info("Loaded from cache. No model call.")
            try:
                _show_investigation_view(investigation_view(load_run()), controls=False)
            except (OSError, ValueError, TypeError):
                st.error("No offline cache was found.")
    elif st.button("Investigate"):
        try:
            with st.spinner("Investigating..."):
                result = triage(frame)
                save_run(payload_from_incident(result))
                st.session_state["investigation"] = result
        except Exception as exc:  # noqa: BLE001
            st.exception(exc)
    if not use_cache:
        investigation = st.session_state.get("investigation")
        if investigation is not None:
            _show_investigation(investigation)

if frame.empty:
    st.info("No events loaded.")
else:
    st.dataframe(frame.head(50))

st.subheader("Upload a log")
st.caption("JSON or JSONL. Bad lines are skipped, counted, and quarantined.")
uploaded = st.file_uploader("Upload a JSON or JSONL log", type=["json", "jsonl"])
if uploaded is not None:
    try:
        upload_dir = Path(tempfile.mkdtemp(prefix="titanlog-upload-"))
        target = upload_dir / Path(uploaded.name).name
        target.write_bytes(uploaded.getvalue())
        uploaded_frame, report = ingest_file(target)
    except OSError:
        st.error("Could not read that file.")
    else:
        _show_report(uploaded_frame, report)
