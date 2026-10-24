"""Titan.Log: trust layer for autonomous SOC investigation agents.

triage() investigates in titan mode and then runs the Oracle.
verify() is the Oracle only and does not call an LLM.
The public demo reads a saved cache and does not call either path live.
"""

from __future__ import annotations

from claims import Claim, ClaimVerdict
from correlate import Incident
from titanlog.schema import Event

Verdict = ClaimVerdict

__all__ = [
    "Claim",
    "Incident",
    "Verdict",
    "triage",
    "verify",
]


def verify(claims: list[Claim], events: list[Event]) -> list[Verdict]:
    """Check claims against events. No LLM call."""
    from oracle import verify_all

    return verify_all(claims, events)


def triage(events: list[Event]) -> Incident:
    """Detect, correlate, investigate in titan mode, verify claims, and recommend a gate."""
    from agents import decision_from_verdicts, investigate, recommend_gate
    from correlate import correlate
    from detectors import detect
    from inject_scan import scan_events

    alerts = detect(events)
    incident = correlate(events, alerts)
    investigation = investigate(incident, events, alerts, mode="titan")
    verdicts = verify(investigation.claims, events)
    severity, close, rationale = decision_from_verdicts(alerts, investigation.claims, verdicts)
    tai = bool(scan_events(events))
    return incident.model_copy(
        update={
            "claims": investigation.claims,
            "verdicts": verdicts,
            "severity": severity,
            "close": close,
            "rationale": rationale,
            "gate": recommend_gate(investigation.claims, verdicts, tai=tai),
            "model_id": investigation.model_id,
            "base_url_host": investigation.base_url_host,
            "llm_fallback": investigation.fallback,
            "investigation_mode": investigation.mode,
        }
    )
