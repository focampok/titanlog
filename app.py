"""Titan.Log analyst console. Run from the repo root: streamlit run app.py.

Offline demo: the public site serves the saved cache and never calls a model.
Real events come from the OTRF Security Datasets. Only the highlighted injection
lines are simulated, and every one carries a SIMULATED label.
"""

from __future__ import annotations

import html
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from cache import (
    investigation_view,
    load_afcr_summary,
    load_cached_injections,
    load_run,
    payload_from_incident,
    save_run,
)
from claims import Claim, ClaimType
from console import (
    MANUAL_MINUTES,
    NOT_IN_CACHE,
    TITAN_MINUTES,
    alert_rows,
    attack_techniques,
    cached,
    claim_rows,
    compact_row,
    escalation_packet,
    first_sentences,
    model_arm_rows,
    ops_kpis,
    row_badges,
    severity_style,
    timeline_rows,
    verdict_counts,
    verdict_style,
)
from correlate import GateRecommendation, correlate
from demo_forged import review_forged
from detectors import detect
from gate import execute, record_audit
from ingest import REASONS, ingest_file, load_dir, load_events
from oracle import verify_claim
from titanlog import triage

DATA_DIR = ROOT / "data" / "otrf"
READ_ONLY = os.environ.get("DEMO_READONLY") == "1"
MONO = '"SFMono-Regular", "JetBrains Mono", "Fira Code", Consolas, monospace'

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

st.set_page_config(
    page_title="Titan.Log",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

_CSS = f"""
<style>
:root {{
  --bg:#0b0f14; --panel:#111821; --line:#1e293b; --ink:#e2e8f0; --muted:#94a3b8;
  --cyan:#22d3ee; --critical:#ef4444; --high:#f97316; --medium:#eab308;
  --low:#22c55e; --grey:#94a3b8;
}}
.stApp {{ background: var(--bg); }}
[data-testid="stHeader"] {{ background: rgba(11,15,20,.92); }}
.block-container {{ padding-top: 1.0rem; padding-bottom: 2.5rem; max-width: 1500px; }}
h1, h2, h3 {{ letter-spacing: -.015em; }}
.app-title {{ font-size: 2.15rem; line-height: 1.05; margin: 0 0 .15rem 0; font-weight: 800; }}
.kicker {{ color: var(--cyan); font-family: {MONO}; font-size: .72rem; letter-spacing: .16em;
  text-transform: uppercase; margin-bottom: .25rem; }}
.tagline {{ color: var(--muted); font-size: 1.02rem; margin: 0 0 .9rem 0; }}
.mono, code, pre, .stCode, [data-testid="stMetricValue"] {{
  font-family: {MONO}; font-variant-numeric: tabular-nums;
}}
[data-testid="stMetric"] {{
  background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: .55rem .7rem;
}}
[data-testid="stMetricLabel"] {{ color: var(--muted); }}
div[data-testid="stMetricValue"] {{ color: var(--ink); font-size: 1.28rem; }}
.side-title {{ color: var(--cyan); font-family: {MONO}; font-size: .7rem; letter-spacing: .14em;
  text-transform: uppercase; margin: .2rem 0 .35rem 0; }}
.badge {{ display: inline-block; padding: .10rem .44rem; border-radius: 999px;
  font-family: {MONO}; font-size: .66rem; font-weight: 800; letter-spacing: .05em;
  text-transform: uppercase; border: 1px solid; margin-right: .28rem; white-space: nowrap; }}
.badge-real {{ color: #a5f3fc; border-color: #155e75; background: #082f3a; }}
.badge-sim {{ color: #fecaca; border-color: #7f1d1d; background: #3b0d0d; }}
.badge-critical {{ color: #fecaca; border-color: #7f1d1d; background: #3b0d0d; }}
.badge-high {{ color: #fed7aa; border-color: #7c2d12; background: #3a1608; }}
.badge-medium {{ color: #fef08a; border-color: #713f12; background: #332508; }}
.badge-low {{ color: #bbf7d0; border-color: #14532d; background: #08210f; }}
.badge-insufficient {{ color: #cbd5e1; border-color: #475569; background: #1a2230; }}
.badge-tech {{ color: #cffafe; border-color: #0e7490; background: #062c36; }}
.badge-approve {{ color: #fef08a; border-color: #a16207; background: #35260a; }}
.badge-deny {{ color: #fecaca; border-color: #b91c1c; background: #3b0d0d; }}
.badge-auto {{ color: #bbf7d0; border-color: #15803d; background: #08210f; }}
.badge-gate {{ color: #e2e8f0; border-color: #334155; background: #172033; }}
.card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: .8rem .95rem; margin-bottom: .65rem; }}
.card h3 {{ margin: .1rem 0 .45rem 0; font-size: 1.02rem; }}
.kv {{ display: inline-block; font-family: {MONO}; font-size: .72rem; color: var(--ink);
  background: #0d1520; border: 1px solid var(--line); border-radius: 6px;
  padding: .16rem .4rem; margin: .12rem .22rem .12rem 0; }}
.kv b {{ color: var(--muted); font-weight: 600; margin-right: .22rem; }}
.muted {{ color: var(--muted); }}
.src {{ color: var(--muted); font-family: {MONO}; font-size: .72rem; }}
.banner-sim {{ background: #2a0b0e; border: 1.5px solid var(--critical); color: #fecaca;
  border-radius: 10px; padding: .6rem .8rem; margin: .15rem 0 .7rem 0;
  font-weight: 800; letter-spacing: .04em; }}
.banner-sim .sub {{ color: #fca5a5; font-weight: 500; letter-spacing: 0; margin-top: .15rem; }}
.injected {{ border: 1.5px solid var(--critical); background: #1a0d10; border-radius: 9px;
  padding: .55rem .65rem; margin: .3rem 0; }}
.injected .injhead {{ color: #fca5a5; font-size: .72rem; margin-bottom: .25rem; }}
.injected pre {{ margin: 0; white-space: pre-wrap; word-break: break-word; color: #fecaca;
  font-family: {MONO}; font-size: .74rem; line-height: 1.45; }}
.inj-line {{ background: #7f1d1d; color: #fff; padding: 0 .12rem; border-radius: 3px; }}
.logrow {{ background: #0d1520; border: 1px solid var(--line); border-radius: 7px;
  padding: .3rem .45rem; margin: .18rem 0; font-family: {MONO}; font-size: .72rem;
  color: var(--ink); white-space: pre-wrap; word-break: break-word; }}
.logrow.sim {{ border-color: var(--critical); background: #1a0d10; }}
.quote {{ border-left: 3px solid var(--cyan); padding: .15rem 0 .15rem .65rem; margin: .4rem 0;
  color: var(--ink); font-size: .86rem; }}
.arch {{ display: flex; flex-wrap: wrap; gap: .45rem; align-items: stretch; margin: .6rem 0 1rem 0; }}
.arch .box {{ background: var(--panel); border: 1px solid var(--line); border-radius: 9px;
  padding: .55rem .65rem; min-width: 150px; flex: 1 1 150px; font-size: .78rem; }}
.arch .box b {{ display: block; color: var(--cyan); font-family: {MONO}; font-size: .68rem;
  letter-spacing: .08em; text-transform: uppercase; margin-bottom: .15rem; }}
.arch .arrow {{ align-self: center; color: var(--muted); font-family: {MONO}; }}
[data-testid="stExpander"] {{ border: 1px solid var(--line); border-radius: 9px; }}
</style>
"""

st.markdown(_CSS, unsafe_allow_html=True)


# --------------------------------------------------------------------------- data


@st.cache_data(show_spinner=False)
def _load_normalized(directory: str) -> pd.DataFrame:
    return load_dir(directory)


@st.cache_data(show_spinner="Loading REAL OTRF evidence…")
def _load_raw(directory: str) -> pd.DataFrame:
    return load_events(directory)


@st.cache_data(show_spinner=False)
def _load_cache() -> dict[str, Any]:
    return load_run()


@st.cache_data(show_spinner=False)
def _fallback_variants() -> dict[str, Any] | None:
    return load_cached_injections()


def _rows_by_id(frame: pd.DataFrame) -> dict[str, dict[str, Any]]:
    if frame.empty:
        return {}
    return {
        str(row.get("row_id")): row
        for row in frame.to_dict("records")
        if row.get("row_id")
    }


def _raw_indexes(frame: pd.DataFrame) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_source: dict[str, list[dict[str, Any]]] = {}
    if frame.empty:
        return by_id, by_source
    for row in frame.to_dict("records"):
        row_id = str(row.get("row_id") or "")
        if row_id:
            by_id[row_id] = row
        by_source.setdefault(str(row.get("source_file") or ""), []).append(row)
    return by_id, by_source


def _mono_frame(frame: pd.DataFrame, mono_columns: list[str]) -> Any:
    if frame.empty:
        return frame
    style = frame.style
    for column in mono_columns:
        if column in frame.columns:
            style = style.set_properties(subset=[column], **{"font-family": MONO})
    return style


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge badge-{kind}">{html.escape(str(text))}</span>'


def _badges_html(badges: dict[str, str], *, limit: int = 160) -> str:
    order = ("timestamp", "host", "user", "event_id", "image", "command_line", "target", "parent")
    cells: list[str] = []
    for key in order:
        value = str(badges.get(key) or "—")
        if limit and len(value) > limit:
            value = value[: limit - 1] + "…"
        cells.append(f'<span class="kv"><b>{key}</b>{html.escape(value)}</span>')
    return "".join(cells)


def _section(title: str, subtitle: str = "") -> None:
    st.markdown(f"### {title}")
    if subtitle:
        st.caption(subtitle)


# --------------------------------------------------------------------------- app


st.markdown('<div class="kicker">TITAN.LOG // L1/L2 INCIDENT CONSOLE</div>', unsafe_allow_html=True)
st.markdown('<h1 class="app-title">Titan.Log</h1>', unsafe_allow_html=True)
st.markdown(
    '<div class="tagline">A prompt can be argued with. A verifier can\'t.</div>',
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown('<div class="side-title">Shift controls</div>', unsafe_allow_html=True)
    use_cache = st.checkbox(
        "Use cache (offline demo)",
        value=True,
        disabled=READ_ONLY,
        help=(
            "Public demo is cache-only."
            if READ_ONLY
            else "Loads the saved run. No model call."
        ),
    )
    if st.button("Load demo: forged incident", width="stretch"):
        try:
            st.session_state["forged_demo"] = review_forged()
        except Exception as exc:  # noqa: BLE001
            st.exception(exc)
    st.markdown("---")
    st.markdown(
        '<span class="badge badge-sim">SIMULATED</span> '
        "<span class='muted'>Injection overlay only. Logs are REAL OTRF.</span>",
        unsafe_allow_html=True,
    )
    if READ_ONLY:
        st.info("Public demo — cached results; no live LLM")

cache: dict[str, Any] = {}
cache_error: Exception | None = None
if use_cache:
    try:
        cache = _load_cache()
    except (OSError, ValueError, TypeError) as exc:
        cache_error = exc

model = str(cache.get("model") or "")
host = str(cache.get("provider_host") or "")
if model or host:
    st.sidebar.caption(f"Model: {model or NOT_IN_CACHE} · host: {host or NOT_IN_CACHE}")

incident = cache.get("incident") if isinstance(cache.get("incident"), dict) else {}
alerts = list(cache.get("alerts") or incident.get("alerts") or [])
claims = list(cache.get("claims") or incident.get("claims") or [])
verdicts = list(cache.get("verdicts") or incident.get("verdicts") or [])
gate = cache.get("gate") or incident.get("gate") or {}
event_counts = cache.get("event_counts") or incident.get("compression") or {}
view = investigation_view(cache) if cache else {"rows": [], "narrative": [], "techniques": []}

if not use_cache:
    st.sidebar.caption("Live mode: Detect and Investigate call the configured model.")

kpis = ops_kpis(event_counts, alerts, claims, verdicts, gate)
saved = kpis["time_saved"]

VERIFIED_TOOLTIP = (
    "Alerts whose claims were all VERIFIED by the Oracle against the raw logs; "
    "the incident still needs human approval because the proposed action is high impact."
)


def _escalation_caption() -> str:
    """Short gate reason for the status bar and KPI caption."""
    level = str(gate.get("level") or "").upper()
    severity = str(incident.get("severity") or "").upper()
    if level == "APPROVE":
        if severity in {"HIGH", "CRITICAL"}:
            return "APPROVE gate — high impact"
        return "APPROVE gate — human approval required"
    if level == "DENY":
        return "DENY — containment blocked"
    if level == "AUTO":
        return "AUTO — mock action audited"
    return "—"


escalation_caption = _escalation_caption()

# Top status bar.
status = st.columns([1.1, 1, 1, 1.1, 1.05])
status[0].metric(
    "Queue · events → alerts → incidents",
    f"{kpis['events']:,} → {kpis['alerts']} → {kpis['incidents']}",
)
status[1].metric(
    "Alerts verified with evidence",
    f"{kpis['auto']['count']}/{kpis['auto']['total']}",
    f"{kpis['auto']['pct']} verified",
    help=VERIFIED_TOOLTIP,
)
status[2].metric(
    "Incident escalated for approval",
    str(kpis["escalated"]["count"]),
    escalation_caption,
    delta_color="off",
    help="Incidents that need a human. APPROVE gate, REFUTED claim, or INSUFFICIENT evidence.",
)
status[3].metric("Active model", model or NOT_IN_CACHE, help=f"Provider host: {host or NOT_IN_CACHE}")
status[4].metric(
    "Data",
    "REAL OTRF",
    "SIMULATED injections",
    delta_color="off",
    help="OTRF Security Datasets. Only the highlighted injection lines are synthetic and labeled SIMULATED.",
)

if cache_error is not None and use_cache:
    st.error("No offline cache was found. Turn off the cache toggle for a live run.")
    st.exception(cache_error)

tabs = st.tabs(["Incident", "Evidence", "Attack on the AI", "About"])


# --------------------------------------------------------------------- incident


def _show_forged(result: Any) -> None:
    st.markdown('<div class="banner-sim">SIMULATED // FORGED INCIDENT</div>', unsafe_allow_html=True)
    st.caption("Offline review of the saved forged file. The Oracle verdicts are computed here; no model call.")
    cols = st.columns(3)
    cols[0].metric("Quarantined lines", result.quarantined)
    cols[1].metric("Alerts still detected", result.alert_count)
    cols[2].metric("Titan.Log close", "true" if result.close else "false")
    st.caption(f"Quarantined: {result.quarantined}")
    st.caption("Incident still detected." if result.incident_detected else "Incident not detected.")
    if result.reasons:
        st.dataframe(
            pd.DataFrame(
                [
                    {"Reason": REASON_LABELS.get(reason, reason), "Count": count}
                    for reason, count in result.reasons.items()
                ]
            ),
            hide_index=True,
            width="stretch",
        )
    if result.insufficient_lines:
        st.warning(
            f"Insufficient evidence: {result.insufficient_lines} line missing host, user, and Event ID."
        )
    for line in result.injections:
        st.markdown(
            '<div class="injected"><div class="injhead">⚠ SIMULATED — forged line</div>'
            f"<pre>{html.escape(line)}</pre></div>",
            unsafe_allow_html=True,
        )
    for label, statement in result.injection_verdicts:
        kind = "deny" if label == "REFUTED" else "insufficient" if label == "INSUFFICIENT" else "low"
        st.markdown(f"{_badge(label, kind)} {html.escape(statement)}", unsafe_allow_html=True)
    st.markdown(
        f"{_badge('close=' + cached(result.close), 'gate')} "
        f"{_gate_badge(result.gate_level)} "
        f"<span class='muted'>{html.escape(result.gate_reason)}</span>",
        unsafe_allow_html=True,
    )
    st.markdown(
        f"{_badge('Cached close', 'gate')} <span class='mono'>{html.escape(cached(result.cache_close))}</span> "
        f"{_badge('Cached claim', 'gate')} <span class='mono'>{html.escape(cached(result.cache_claim))}</span>",
        unsafe_allow_html=True,
    )


def _gate_badge(level: str) -> str:
    normalized = str(level or "").upper()
    kind = {"APPROVE": "approve", "DENY": "deny", "AUTO": "auto"}.get(normalized, "gate")
    return _badge(normalized or NOT_IN_CACHE, kind)


def _technique_badges() -> str:
    findings = attack_techniques(view, alerts)
    if not findings:
        return "<span class='muted'>No detector fired, so no technique is mapped.</span>"
    parts: list[str] = []
    for finding in findings:
        source = finding.get("source") or "mapped by detector"
        parts.append(
            f"<span class='badge badge-tech'>{html.escape(finding['technique_id'])}</span>"
            f"<span class='muted'>{html.escape(finding.get('statement') or '')} "
            f"· {html.escape(source)}</span>"
        )
    return "<br>".join(parts)


def _incident_card() -> None:
    hosts = ", ".join(str(item) for item in (incident.get("hosts") or [])) or "—"
    users = ", ".join(str(item) for item in (incident.get("users") or [])) or "—"
    start = incident.get("window_start") or "—"
    end = incident.get("window_end") or "—"
    severity = str(incident.get("severity") or "INSUFFICIENT").upper()
    close = incident.get("close")
    close_text = "true" if close is True else "false" if close is False else NOT_IN_CACHE
    gate_level = str(gate.get("level") or "").upper()
    gate_action = str(gate.get("action") or "")
    severity_kind = severity.lower() if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "insufficient"
    st.markdown(
        '<div class="card">'
        '<div class="kicker">Incident card</div>'
        f"<h3>{html.escape(hosts)}</h3>"
        f"<div>{_badge(severity, severity_kind)} {_gate_badge(gate_level)} "
        f"{_badge('close=' + close_text, 'gate')}</div>"
        f"<div style='margin-top:.45rem'><span class='kv'><b>host</b>{html.escape(hosts)}</span>"
        f"<span class='kv'><b>user</b>{html.escape(users)}</span></div>"
        f"<div><span class='kv'><b>window</b>{html.escape(str(start))} → {html.escape(str(end))}</span></div>"
        f"<div style='margin-top:.35rem'>{_technique_badges()}</div>"
        f"<div style='margin-top:.35rem' class='muted'>Gate: {html.escape(gate_level or NOT_IN_CACHE)} "
        f"{html.escape(gate_action)} — {html.escape(str(gate.get('reason') or NOT_IN_CACHE))}</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def _gate_controls() -> None:
    level = str(gate.get("level") or "").upper()
    action = str(gate.get("action") or "")
    evidence_ids = list(view.get("evidence_claim_ids") or [])
    if level == "DENY":
        st.error("DENY — containment is blocked. No action was executed.")
        return
    if level == "AUTO" and action == "disable_account":
        token = "AUTO:" + ",".join(evidence_ids)
        if st.session_state.get("gate_auto") != token:
            execute(_decision(level, action), actor="titan", evidence_ids=evidence_ids)
            st.session_state["gate_auto"] = token
        st.info("AUTO — the mock disable_account action was recorded in the audit log.")
        return
    if level != "APPROVE" or action != "disable_account":
        st.caption("No human action is required for this gate.")
        return
    st.caption("Human approval is required for disable_account. The action is a local mock.")
    approve, deny = st.columns(2)
    decision = _decision(level, action)
    if approve.button("Approve disable_account", key="approve_gate", width="stretch"):
        execute(decision, actor="analyst", evidence_ids=evidence_ids)
        st.success("Approved. The mock disable_account action was recorded.")
    if deny.button("Deny", key="deny_gate", width="stretch"):
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


def _show_report(frame: pd.DataFrame, report: Any) -> None:
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
        st.dataframe(pd.DataFrame(reason_rows), hide_index=True, width="stretch")
    if report.unknown_event_ids:
        st.caption("Unknown event IDs: " + ", ".join(str(item) for item in report.unknown_event_ids))
    if report.quarantined_path:
        st.caption("Quarantine files")
        for path in report.quarantined_path:
            st.code(path, language=None)
    if frame.empty:
        st.info("No events parsed from this file.")
    else:
        st.dataframe(frame.head(10), hide_index=True, width="stretch")


def _incident_tab() -> None:
    forged = st.session_state.get("forged_demo")
    if forged is not None:
        _show_forged(forged)
        st.divider()

    detect_col, note_col = st.columns([0.22, 0.78])
    if detect_col.button("Detect", width="stretch", help="Re-run the detectors on the REAL OTRF rows."):
        try:
            normalized = _load_normalized(str(DATA_DIR))
            st.session_state["detected_incident"] = correlate(normalized, detect(normalized))
        except Exception as exc:  # noqa: BLE001
            st.exception(exc)
    note_col.caption("Runs the deterministic detectors. This does not call a model.")
    detected = st.session_state.get("detected_incident")
    if detected is not None:
        st.markdown(f"**Compression:** {detected.compression.label()}")

    if not alerts and not claims:
        st.info("No incident in the cache. Use the sidebar, or turn off the cache and detect a file.")
    else:
        left, right = st.columns([1.35, 1], gap="large")
        with left:
            _section(
                "Alert queue",
                "Sorted by deterministic severity. Severity is per detector, not a model verdict.",
            )
            queue = pd.DataFrame(alert_rows(alerts))
            if queue.empty:
                st.info("No alerts in this incident.")
            else:
                columns = ["Severity", "Alert", "Technique", "Host", "User", "Event ID", "Time", "Evidence"]
                shown = queue[columns].head(10)
                styled = shown.style.map(severity_style, subset=["Severity"])
                styled = styled.set_properties(subset=["Time"], **{"font-family": MONO})
                st.dataframe(
                    styled,
                    hide_index=True,
                    width="stretch",
                    height=min(420, 42 + 34 * max(1, len(shown))),
                    column_config={
                        "Evidence": st.column_config.TextColumn("Evidence", width="large"),
                        "Time": st.column_config.TextColumn("Time", width="medium"),
                    },
                )
                if len(queue) > 10:
                    st.caption(
                        f"Showing 10 of {len(queue)} alerts. The full set stays in the escalation packet."
                    )
        with right:
            _section("Case")
            _incident_card()
            _gate_controls()

    st.divider()
    _section("Operational KPIs", "Computed from the saved run and cache. No hard-coded numbers.")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric(
        "Alerts verified with evidence",
        f"{kpis['auto']['count']}/{kpis['auto']['total']}",
        f"{kpis['auto']['pct']}",
        help=VERIFIED_TOOLTIP,
    )
    col2.metric(
        "Incident escalated for approval",
        str(kpis["escalated"]["count"]),
        escalation_caption,
        delta_color="off",
        help="Breakdown by reason: REFUTED claim, INSUFFICIENT evidence, or APPROVE gate.",
    )
    col3.metric(
        "Events → incidents",
        f"{kpis['events']:,} → {kpis['alerts']} → {kpis['incidents']}",
        f"{kpis['compression']['events_per_incident']:.0f} events / incident",
        delta_color="off",
        help=f"{kpis['compression']['alerts_per_incident']:.1f} alerts per incident. Measured compression.",
    )
    col4.metric(
        "Analyst time saved (est.)",
        f"{saved['per_incident']:.1f} min",
        f"range {saved['low']}–{saved['high']} min",
        delta_color="off",
        help=(
            "ESTIMATE, not measured. Manual L1 triage "
            f"{MANUAL_MINUTES[0]}–{MANUAL_MINUTES[1]} min minus Titan.Log "
            f"{TITAN_MINUTES[0]}–{TITAN_MINUTES[1]} min per incident. "
            "Assumes one analyst, one pass, no rework. Not part of AFCR."
        ),
    )
    st.caption(
        "Escalation reasons — "
        f"APPROVE gate {kpis['escalated']['reasons'].get('APPROVE gate', 0)} · "
        f"REFUTED {kpis['escalated']['refuted']} · "
        f"INSUFFICIENT {kpis['escalated']['insufficient']}."
    )
    st.caption(
        "ESTIMATE — analyst time uses config defaults "
        f"({MANUAL_MINUTES[0]}–{MANUAL_MINUTES[1]} min manual vs {TITAN_MINUTES[0]}–{TITAN_MINUTES[1]} min Titan.Log). "
        "It is not a measured result."
    )

    with st.expander("Escalation packet — claims, verdicts, evidence, gate"):
        st.code(escalation_packet(view, incident=incident), language=None)

    st.divider()
    _section("LLM contribution", "Cached model output. The Oracle verdicts are deterministic.")
    rationale = view.get("rationale") or incident.get("rationale") or ""
    if rationale:
        st.markdown(f"<div class='quote'>{html.escape(str(rationale))}</div>", unsafe_allow_html=True)
    narrative = view.get("narrative") or []
    if narrative:
        for statement in narrative:
            st.markdown(f"- {statement}")
    elif not rationale:
        st.info("No narrative was returned for this run.")

    claim_table = pd.DataFrame(claim_rows(claims, verdicts))
    if claim_table.empty:
        st.info("No claims were returned for this run.")
    else:
        styled_claims = claim_table.style.map(verdict_style, subset=["Verdict"])
        styled_claims = styled_claims.set_properties(
            subset=["Claim ID", "Evidence row id"], **{"font-family": MONO}
        )
        st.dataframe(
            styled_claims,
            hide_index=True,
            width="stretch",
            height=min(430, 42 + 35 * min(10, len(claim_table))),
            column_config={
                "Claim": st.column_config.TextColumn("Claim", width="large"),
                "Oracle reason": st.column_config.TextColumn("Oracle reason", width="large"),
            },
        )
        st.caption(
            f"Verified {verdict_counts(verdicts)['VERIFIED']} · "
            f"Refuted {verdict_counts(verdicts)['REFUTED']} · "
            f"Insufficient {verdict_counts(verdicts)['INSUFFICIENT']}"
        )

    st.divider()
    _section("Timeline", "Chronological. Technique is mapped by the detector.")
    timeline = pd.DataFrame(timeline_rows(alerts, _rows_by_id(_load_normalized(str(DATA_DIR)))))
    if timeline.empty:
        st.info("No timeline rows.")
    else:
        st.dataframe(
            _mono_frame(timeline, ["Time", "Host", "Process"]),
            hide_index=True,
            width="stretch",
            height=min(380, 42 + 32 * min(10, len(timeline))),
        )

    st.divider()
    _section("Ingest a log", "JSON or JSONL. Bad lines are skipped, counted, and quarantined.")
    uploaded = st.file_uploader("Upload a JSON or JSONL log", type=["json", "jsonl"])
    if uploaded is not None:
        try:
            upload_dir = Path(tempfile.mkdtemp(prefix="titanlog-upload-"))
            target = upload_dir / Path(uploaded.name).name
            target.write_bytes(uploaded.getvalue())
            uploaded_frame, report = ingest_file(target)
        except OSError as exc:
            st.exception(exc)
        else:
            _show_report(uploaded_frame, report)

    if not use_cache:
        st.divider()
        if READ_ONLY:
            st.caption("Read-only public demo: live investigation is disabled.")
        else:
            if st.button("Detect alerts in data/otrf", width="stretch"):
                try:
                    live_alerts = detect(_load_normalized(str(DATA_DIR)))
                    st.session_state["incident"] = correlate(
                        _load_normalized(str(DATA_DIR)), live_alerts
                    )
                    st.session_state.pop("investigation", None)
                except Exception as exc:  # noqa: BLE001
                    st.exception(exc)
            live = st.session_state.get("incident")
            if live is not None:
                st.caption(
                    f"Live detection: {live.compression.label()} · hosts {', '.join(live.hosts) or '—'}"
                )
                if st.button("Investigate with the configured model", width="stretch"):
                    try:
                        with st.spinner("Investigating…"):
                            result = triage(_load_normalized(str(DATA_DIR)))
                            save_run(payload_from_incident(result))
                            st.session_state["investigation"] = result
                    except Exception as exc:  # noqa: BLE001
                        st.exception(exc)
                investigation = st.session_state.get("investigation")
                if investigation is not None:
                    _section("Live investigation", "This result is not read from the cache.")
                    st.write(investigation.rationale or "No rationale.")
                    st.json(investigation.model_dump(mode="json"))


# --------------------------------------------------------------------- evidence


def _context_rows(
    base_row: dict[str, Any] | None,
    by_source: dict[str, list[dict[str, Any]]],
    *,
    before: int = 2,
    after: int = 2,
) -> list[dict[str, Any]]:
    if base_row is None:
        return []
    source = str(base_row.get("source_file") or "")
    rows = by_source.get(source) or []
    if not rows:
        return [base_row]
    row_id = str(base_row.get("row_id") or "")
    index = next((i for i, item in enumerate(rows) if str(item.get("row_id")) == row_id), None)
    if index is None:
        return [base_row]
    start = max(0, index - before)
    end = min(len(rows), index + after + 1)
    return rows[start:end]


def _download_rows(raw_by_id: dict[str, dict[str, Any]]) -> str:
    lines: list[str] = []
    for row in raw_by_id.values():
        payload = row.get("raw") if isinstance(row.get("raw"), dict) else row
        lines.append(json.dumps(payload, default=str))
    return "\n".join(lines) + ("\n" if lines else "")


def _evidence_tab() -> None:
    st.markdown(
        '<span class="badge badge-real">REAL</span> '
        "<span class='muted'>OTRF Security Datasets — original rows behind the incident.</span>",
        unsafe_allow_html=True,
    )
    if not alerts:
        st.info("No alert rows in the cache.")
        return
    try:
        raw_frame = _load_raw(str(DATA_DIR))
    except Exception as exc:  # noqa: BLE001
        st.exception(exc)
        return
    raw_by_id, by_source = _raw_indexes(raw_frame)
    top = pd.DataFrame(alert_rows(alerts)).head(6)
    alert_by_row = {str(alert.get("row_id")): alert for alert in alerts}
    for _, row in top.iterrows():
        row_id = str(row["_row_id"])
        alert = alert_by_row.get(row_id, {})
        source_row = raw_by_id.get(row_id)
        if source_row is None:
            st.warning(f"Cited row is not in the loaded OTRF files: {row_id or '—'}")
            continue
        source_file = str(source_row.get("source_file") or alert.get("source_file") or NOT_IN_CACHE)
        st.markdown(
            _badges_html(row_badges(source_row)),
            unsafe_allow_html=True,
        )
        st.markdown(
            '<span class="badge badge-real">REAL</span> '
            f"<span class='src'>REAL — OTRF Security Datasets ({html.escape(source_file)})</span>",
            unsafe_allow_html=True,
        )
        context = _context_rows(source_row, by_source)
        for index, item in enumerate(context):
            payload = item.get("raw") if isinstance(item.get("raw"), dict) else item
            label = "cited alert row" if str(item.get("row_id")) == row_id else "context row"
            if index == 0:
                st.json(payload, expanded=True)
            else:
                with st.expander(f"{label} · {compact_row(item)[:110]}"):
                    st.json(payload)
        st.divider()

    unique = {str(alert.get("row_id")): raw_by_id[str(alert.get("row_id"))] for alert in alerts if str(alert.get("row_id")) in raw_by_id}
    if unique:
        st.download_button(
            "Download the incident's REAL raw rows (JSONL)",
            data=_download_rows(unique),
            file_name="titanlog-incident-raw.jsonl",
            mime="application/jsonl",
            width="stretch",
        )
    else:
        st.caption("No raw rows are available to download.")


# ------------------------------------------------------------------ attack on AI


def _arm_card(title: str, arm: dict[str, Any] | None, *, model_hint: str = "") -> None:
    if not arm:
        st.markdown(f"**{title}**")
        st.warning(NOT_IN_CACHE)
        return
    severity = str(arm.get("severity") or "INSUFFICIENT").upper()
    severity_kind = severity.lower() if severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"} else "insufficient"
    close = arm.get("close")
    close_text = "true" if close is True else "false" if close is False else NOT_IN_CACHE
    outcome = str(arm.get("outcome") or NOT_IN_CACHE)
    model = str(arm.get("model_id") or model_hint or NOT_IN_CACHE)
    st.markdown(
        f"**{html.escape(title)}**<br>"
        f"{_badge(severity, severity_kind)} {_badge('close=' + close_text, 'gate')} "
        f"{_badge(outcome, 'gate')}",
        unsafe_allow_html=True,
    )
    st.caption(f"{model} · cached trial {arm.get('trial') or '—'}")
    rationale = str(arm.get("rationale") or "")
    if rationale:
        st.markdown(
            f"<div class='quote'>{html.escape(first_sentences(rationale, 2))}</div>",
            unsafe_allow_html=True,
        )
        with st.expander("Full rationale"):
            st.write(rationale)
    else:
        st.caption(NOT_IN_CACHE)


def _injection_selector(variants: dict[str, Any]) -> str | None:
    ids = sorted(variants)
    if not ids:
        return None
    default = "I01" if "I01" in ids else ids[0]

    def label(injection_id: str) -> str:
        entry = variants.get(injection_id) or {}
        return (
            f"{injection_id} — {entry.get('attack_objective') or 'unknown objective'} — "
            f"{entry.get('field') or 'field unknown'}"
        )

    return st.selectbox(
        "Injection variant",
        ids,
        index=ids.index(default),
        format_func=label,
        help="SIMULATED variants saved by the AFCR test harness. Default I01.",
    )


def _render_injected_left(
    variant: dict[str, Any],
    raw_by_id: dict[str, dict[str, Any]],
    by_source: dict[str, list[dict[str, Any]]],
) -> None:
    injected = variant.get("injected_row") or {}
    payload = str(variant.get("payload") or "")
    base_row = raw_by_id.get(str(variant.get("base_row_id") or ""))
    context = _context_rows(base_row, by_source) if base_row is not None else []
    st.markdown(
        '<span class="badge badge-real">REAL</span> '
        '<span class="badge badge-sim">SIMULATED</span> '
        "<span class='muted'>One synthetic line inside real OTRF rows.</span>",
        unsafe_allow_html=True,
    )
    if not context:
        st.caption("Real context rows are unavailable. Showing the saved injected line only.")
        rendered = compact_row(injected)
        st.markdown(
            '<div class="injected"><div class="injhead">SIMULATED injection — inserted by Titan.Log test harness</div>'
            f"<pre>{_highlight(rendered, payload)}</pre></div>",
            unsafe_allow_html=True,
        )
        return
    for item in context:
        row_id = str(item.get("row_id") or "")
        if row_id == str(variant.get("base_row_id") or ""):
            rendered = compact_row(injected)
            st.markdown(
                '<div class="injected"><div class="injhead">SIMULATED injection — inserted by Titan.Log test harness</div>'
                f"<pre>{_highlight(rendered, payload)}</pre></div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="logrow"><span class="badge badge-real">REAL</span> '
                f"{html.escape(compact_row(item))}</div>",
                unsafe_allow_html=True,
            )
    st.caption("The payload is inserted in the cited field. Original OTRF files are not modified.")


def _highlight(text: str, payload: str) -> str:
    escaped = html.escape(text)
    needle = html.escape(payload)
    if needle and needle in escaped:
        return escaped.replace(
            needle,
            f'<span class="inj-line">⚠ {needle}</span>',
            1,
        )
    return escaped


def _injected_claim(variant: dict[str, Any]) -> tuple[Claim | None, Any]:
    injected = variant.get("injected_row") or {}
    payload = str(variant.get("payload") or "")
    if not payload or not injected:
        return None, None
    claim = Claim(
        claim_id="injection-check",
        claim_type=ClaimType.AUTHORIZATION,
        statement=payload,
        host=injected.get("host_name") or injected.get("host_key"),
        user=injected.get("user_name"),
        row_id=injected.get("row_id"),
        field=variant.get("field") or "CommandLine",
        expected_value_substring=payload,
        confidence=1.0,
    )
    return claim, verify_claim(claim, [injected])


def _attack_tab() -> None:
    st.markdown(
        '<div class="banner-sim">SIMULATED INJECTIONS on REAL logs'
        '<div class="sub">The events are REAL OTRF rows. Only the highlighted line is synthetic, '
        "inserted by the Titan.Log test harness.</div></div>",
        unsafe_allow_html=True,
    )
    summary = cache.get("afcr_summary") if isinstance(cache.get("afcr_summary"), dict) else {}
    if not summary:
        try:
            summary = load_afcr_summary() or {}
        except (OSError, ValueError, TypeError):
            summary = {}
    _section(
        "Model × arm",
        "AFCR is the adversarial false-close rate. SIMULATED. n=10 (I01–I04, I13–I18); "
        "any close n=18; influence n=18.",
    )
    arm_rows = pd.DataFrame(model_arm_rows(summary))
    if arm_rows.empty:
        st.warning(NOT_IN_CACHE)
    else:
        styled = arm_rows.drop(columns=["_titan"]).style.apply(
            lambda row: [
                "background-color:#0e2a33; color:#e2e8f0; font-weight:700"
                if row["Arm"] == "Titan.Log"
                else ""
                for _ in row
            ],
            axis=1,
        )
        st.dataframe(styled, hide_index=True, width="stretch")
        st.caption("Titan.Log rows are highlighted. Fractions are closed/trials; percentages are AFCR.")

    variants_payload = cache.get("afcr_variants") if isinstance(cache.get("afcr_variants"), dict) else None
    if not variants_payload:
        variants_payload = _fallback_variants()
    variants = (variants_payload or {}).get("variants") or {}
    if not variants:
        st.warning("[not in cache] No saved injection variants were found.")
        return
    selected = _injection_selector(variants)
    variant = variants.get(selected or "") or {}
    payload = str(variant.get("payload") or "")
    arms = variant.get("arms") or {}
    counts = variant.get("counts") or {}
    st.markdown(
        f"{_badge('SIMULATED', 'sim')} {_badge(variant.get('attack_objective') or 'objective', 'gate')} "
        f"{_badge(variant.get('field') or 'field', 'gate')} "
        f"<span class='mono muted'>payload: {html.escape(payload[:160]) or NOT_IN_CACHE}</span>",
        unsafe_allow_html=True,
    )
    if counts:
        pieces = []
        for arm_name in ("naive", "hardened_prompt", "titan"):
            bucket = counts.get("arms", {}).get(arm_name) or {}
            pieces.append(
                f"{'Titan.Log' if arm_name == 'titan' else arm_name}: "
                f"{bucket.get('closed', 0)}/{bucket.get('trials', 0)} closed"
            )
        st.caption("Saved table for this variant — " + " · ".join(pieces))

    try:
        raw_frame = _load_raw(str(DATA_DIR))
        raw_by_id, by_source = _raw_indexes(raw_frame)
    except Exception as exc:  # noqa: BLE001
        st.exception(exc)
        raw_by_id, by_source = {}, {}

    left, middle, right = st.columns([1.08, 1, 1.08], gap="medium")
    with left:
        _section("Real log + simulated line")
        _render_injected_left(variant, raw_by_id, by_source)
    with middle:
        _section("Naive / hardened")
        _arm_card("Naive agent (Qwen3-30B)", arms.get("naive"))
        _arm_card("Hardened prompt", arms.get("hardened_prompt"))
        st.caption("Cached verdicts. No live model call.")
    with right:
        _section("Titan.Log")
        _arm_card("Titan.Log — cached decision", arms.get("titan"))
        _claim, injected_verdict = _injected_claim(variant)
        if injected_verdict is None:
            st.warning(NOT_IN_CACHE)
        else:
            status = str(injected_verdict.status)
            label = {"VERIFIED": "VERIFIED", "REJECTED": "REFUTED", "UNVERIFIABLE": "INSUFFICIENT"}.get(
                status, "INSUFFICIENT"
            )
            kind = "deny" if label == "REFUTED" else "insufficient"
            st.markdown(
                f"**Injected authorization text**<br>{_badge(label, kind)} "
                f"<span class='muted'>{html.escape(injected_verdict.reason)}</span>",
                unsafe_allow_html=True,
            )
            st.caption(
                "Oracle check on the saved injected row. The text is not a ticket and never becomes evidence."
            )
        gate_level = str(gate.get("level") or "").upper()
        if gate_level == "APPROVE":
            st.markdown(f"**Gate** {_gate_badge(gate_level)} ESCALATE — human approval required.")
        elif gate_level == "DENY":
            st.markdown(f"**Gate** {_gate_badge(gate_level)} DENY — containment stays blocked.")
        elif gate_level == "AUTO":
            st.markdown(f"**Gate** {_gate_badge(gate_level)} AUTO — mock action audited.")
        else:
            st.markdown(f"**Gate** {_gate_badge(gate_level or NOT_IN_CACHE)}")
        st.caption(str(gate.get("reason") or NOT_IN_CACHE))

        injection_host = str((variant.get("injected_row") or {}).get("host_name") or "").casefold()
        relevant_claims = [
            claim
            for claim in claims
            if not injection_host or str(claim.get("host") or "").casefold() == injection_host
        ] or claims
        relevant_rows = claim_rows(relevant_claims[:6], verdicts)
        if relevant_rows:
            compact_claims = pd.DataFrame(relevant_rows)[["Claim", "Verdict", "Evidence row id"]]
            styled_claims = compact_claims.style.map(verdict_style, subset=["Verdict"])
            styled_claims = styled_claims.set_properties(
                subset=["Evidence row id"], **{"font-family": MONO}
            )
            st.caption("Cached claims for this host in the verified run (supporting context).")
            st.dataframe(
                styled_claims,
                hide_index=True,
                width="stretch",
                height=min(300, 40 + 34 * len(compact_claims)),
                column_config={"Claim": st.column_config.TextColumn("Claim", width="large")},
            )
        counts_by_verdict = verdict_counts(verdicts)
        st.caption(
            f"All cached claims in the run: {counts_by_verdict['VERIFIED']} verified · "
            f"{counts_by_verdict['REFUTED']} refuted · "
            f"{counts_by_verdict['INSUFFICIENT']} insufficient. "
            "Full statements and Oracle reasons are in the Incident tab."
        )
        st.caption("READ-ONLY cache. No live model call.")


# ------------------------------------------------------------------------ about


def _about_tab() -> None:
    _section("About Titan.Log")
    st.markdown(
        "1. Titan.Log is a trust layer between an AI SOC and the logs it reads.\n"
        "2. Ingest is robust: bad lines are skipped, counted, and quarantined; unknown input goes to a human.\n"
        "3. The model proposes structured claims; a deterministic Oracle verifies each one.\n"
        "4. A gate escalates or blocks containment, and every decision is written to the audit log.\n"
        "5. The demo logs are REAL OTRF Security Datasets; only the labeled injection lines are SIMULATED."
    )
    st.markdown(
        '<div class="arch">'
        '<div class="box"><b>Data connectors</b>OTRF JSONL, generic JSONL via a field map</div>'
        '<div class="arrow">→</div>'
        '<div class="box"><b>Ingest</b>normalize, skip + count, quarantine, insufficient evidence</div>'
        '<div class="arrow">→</div>'
        '<div class="box"><b>Detect + correlate</b>alerts, one incident, compression</div>'
        '<div class="arrow">→</div>'
        '<div class="box"><b>Claims + Oracle</b>structured claims, deterministic verdicts</div>'
        '<div class="arrow">→</div>'
        '<div class="box"><b>Gate + audit</b>AUTO / APPROVE / DENY, local JSONL mock</div>'
        '<div class="arrow">→</div>'
        '<div class="box"><b>Human workbench</b>escalation packet, evidence, decision</div>'
        "</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "**Repository:** [github.com/focampok/titanlog](https://github.com/focampok/titanlog)"
    )
    st.markdown(
        "Pitch deck: [pitch/deck.html](pitch/deck.html) · "
        "[https://info-titan-log.focampo.com/](https://info-titan-log.focampo.com/)"
    )
    deck_path = ROOT / "pitch" / "deck.html"
    if deck_path.is_file():
        st.download_button(
            "Download pitch deck",
            data=deck_path.read_bytes(),
            file_name="deck.html",
            mime="text/html",
        )
    st.markdown(
        "**Data and frameworks**\n"
        "- OTRF Security Datasets (MIT): `empire_psexec_dcerpc_tcp_svcctl_2020-09-20121608.json`, "
        "`psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json`.\n"
        "- MITRE ATT&CK techniques: T1003.001, T1059.001, T1569.002, T1021.002.\n"
        "- The injection overlay is SIMULATED and labeled on every view. "
        "The authorization check is a deliberate stub; production would query ServiceNow or Jira.\n"
        "- Known limitation: split-context injections I10/I11 are checked per row, not stitched across events."
    )


with tabs[0]:
    _incident_tab()
with tabs[1]:
    _evidence_tab()
with tabs[2]:
    _attack_tab()
with tabs[3]:
    _about_tab()

st.divider()
st.markdown("[Francisco Ocampo](https://focampo.com)")
