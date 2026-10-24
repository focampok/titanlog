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

from correlate import correlate
from detectors import detect
from ingest import REASONS, ingest_file, load_dir

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

if st.button("Detect"):
    alerts = detect(frame)
    st.session_state["incident"] = correlate(frame, alerts)

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
