"""Titan.Log event preview. Run from the repo root: streamlit run app.py."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cache import load_run, payload_from_incident, save_run
from correlate import correlate
from detectors import detect
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
}

st.set_page_config(page_title="Titan.Log", layout="wide")
st.title("Titan.Log")
use_cache = st.sidebar.checkbox("Use cache (offline demo)", value=True)
st.sidebar.caption("Skips the model and loads the saved run.")


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

_VERDICT_LABELS = {
    "VERIFIED": "VERIFIED",
    "REJECTED": "REFUTED",
    "UNVERIFIABLE": "INSUFFICIENT",
}


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

    claims = cache.get("claims") or []
    verdicts = {
        item.get("claim_id"): item.get("status")
        for item in (cache.get("verdicts") or [])
        if isinstance(item, dict)
    }
    st.subheader("Cached claims")
    if claims:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Claim": claim.get("statement") or "",
                        "Verdict": _VERDICT_LABELS.get(verdicts.get(claim.get("claim_id"), ""), "INSUFFICIENT"),
                        "Evidence row id": claim.get("row_id") or "",
                    }
                    for claim in claims
                    if isinstance(claim, dict)
                ]
            ),
            hide_index=True,
        )
    else:
        st.info("No cached claims.")
    gate = cache.get("gate")
    if isinstance(gate, dict) and gate.get("level"):
        st.write(f"Gate: {gate.get('level')}. {gate.get('reason') or ''}")


def _show_investigation(result) -> None:
    st.subheader("Narrative")
    narrative = [
        claim.statement
        for claim in result.claims
        if claim.claim_type.value != "attack_technique" and claim.statement
    ]
    if narrative:
        for statement in narrative:
            st.write(statement)
    elif result.rationale:
        st.write(result.rationale)
    else:
        st.info("No narrative was returned.")

    st.subheader("ATT&CK")
    techniques = [claim for claim in result.claims if claim.claim_type.value == "attack_technique"]
    if techniques:
        for claim in techniques:
            label = claim.technique_id or "unknown"
            st.write(f"{label}: {claim.statement}")
    else:
        st.info("No ATT&CK technique was claimed.")

    st.subheader("Claims")
    verdict_by_id = {verdict.claim_id: verdict.status for verdict in result.verdicts}
    rows = [
        {
            "Claim": claim.statement,
            "Verdict": _VERDICT_LABELS.get(verdict_by_id.get(claim.claim_id, ""), "INSUFFICIENT"),
            "Evidence row id": claim.row_id or "",
        }
        for claim in result.claims
    ]
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True)
    else:
        st.info("No claims.")


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
