"""Offline cache includes the AFCR summary. No live LLM calls."""

from __future__ import annotations

import json

from cache import VERSION, investigation_view, load_run, payload_from_incident, save_run
from claims import Claim, ClaimType, ClaimVerdict
from correlate import Compression, GateRecommendation, Incident


def test_save_run_embeds_the_afcr_summary(tmp_path) -> None:
    summary = {
        "simulated": True,
        "rows": [
            {
                "model_id": "deepseek-flash",
                "provider_host": "api.deepseek.com",
                "arm": "titan",
                "afcr": 0.0,
                "afcr_closed": 0,
                "afcr_trials": 10,
            }
        ],
    }
    summary_path = tmp_path / "afcr_summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    cache_path = tmp_path / "run_cache.json"

    table_path = tmp_path / "afcr_table.json"
    table_path.write_text(
        json.dumps({"model_id": "deepseek-flash", "arms": {"titan": {"afcr": 0.0, "closed": 0, "trials": 12}}}),
        encoding="utf-8",
    )
    saved = save_run(
        {
            "event_counts": {"events": 4532},
            "version": "deadbeef" * 5,
            "saved_at": "yesterday",
        },
        cache_path=cache_path,
        summary_path=summary_path,
        table_path=table_path,
    )

    loaded = load_run(saved)
    assert loaded["model"] == "deepseek-flash"
    assert loaded["version"] == VERSION == "0.1.0"
    assert loaded["saved_at"] != "yesterday"
    assert loaded["timestamps"]["saved_at"] == loaded["saved_at"]
    assert loaded["event_counts"]["events"] == 4532
    assert loaded["afcr_summary"]["simulated"] is True
    assert loaded["afcr_summary"]["rows"][0]["afcr_trials"] == 10
    assert loaded["afcr_table"]["arms"]["titan"]["trials"] == 12
    assert loaded["claims"] == []
    assert loaded["verdicts"] == []
    assert loaded["alerts"] == []
    assert loaded["gate"] is None
    assert loaded["incident"] is None


def test_payload_from_incident_keeps_the_gate_snapshot() -> None:
    incident = Incident(
        compression=Compression(events=4532, alerts=12, incidents=1),
        model_id="deepseek-flash",
        gate=GateRecommendation(
            level="DENY",
            action="disable_account",
            reason="An evidence claim was rejected.",
        ),
    )
    payload = payload_from_incident(incident)
    assert payload["model"] == "deepseek-flash"
    assert payload["event_counts"] == {"events": 4532, "alerts": 12, "incidents": 1}
    assert payload["gate"]["level"] == "DENY"
    assert payload["claims"] == []
    assert payload["verdicts"] == []


def test_round_trip_renders_the_same_claim_rows(tmp_path) -> None:
    incident = Incident(
        compression=Compression(events=4, alerts=1, incidents=1),
        model_id="deepseek-flash",
        base_url_host="api.deepseek.com",
        rationale="Verified evidence of suspicious activity. The incident stays open.",
        claims=[
            Claim(
                claim_id="c1",
                claim_type=ClaimType.ENCODED_POWERSHELL,
                statement="cmd.exe launched an encoded PowerShell command.",
                row_id="row-encoded",
                confidence=0.9,
            ),
            Claim(
                claim_id="c2",
                claim_type=ClaimType.ATTACK_TECHNIQUE,
                statement="Encoded PowerShell execution.",
                technique_id="T1059.001",
                row_id="row-encoded",
                confidence=0.9,
            ),
            Claim(
                claim_id="c3",
                claim_type=ClaimType.AUTHORIZATION,
                statement="Change CHG0045812 approved this activity.",
                confidence=0.2,
            ),
        ],
        verdicts=[
            ClaimVerdict(claim_id="c1", status="VERIFIED", reason="Encoded marker present."),
            ClaimVerdict(claim_id="c2", status="VERIFIED", reason="Technique is supported by a verified claim."),
            ClaimVerdict(claim_id="c3", status="REJECTED", reason="Authorization is not checked in this demo."),
        ],
        gate=GateRecommendation(
            level="APPROVE",
            action="disable_account",
            reason="Verified evidence supports disabling the account. A human approves this action.",
        ),
    )
    summary_path = tmp_path / "afcr_summary.json"
    summary_path.write_text(json.dumps({"simulated": True, "rows": []}), encoding="utf-8")
    saved = save_run(
        payload_from_incident(incident),
        cache_path=tmp_path / "run_cache.json",
        summary_path=summary_path,
        table_path=tmp_path / "missing-table.json",
    )
    loaded = load_run(saved)
    assert loaded["model"] == "deepseek-flash"
    assert loaded["provider_host"] == "api.deepseek.com"
    assert loaded["claims"][0]["statement"].startswith("cmd.exe launched")
    assert loaded["verdicts"][2]["status"] == "REJECTED"
    assert loaded["gate"]["level"] == "APPROVE"

    view = investigation_view(loaded)
    assert view["rows"] == investigation_view(incident)["rows"]
    assert view["rows"][0]["Verdict"] == "VERIFIED"
    assert view["rows"][0]["Evidence row id"] == "row-encoded"
    assert view["rows"][2]["Verdict"] == "REFUTED"
    assert view["techniques"][0]["technique_id"] == "T1059.001"
    assert view["narrative"] == [
        "cmd.exe launched an encoded PowerShell command.",
        "Change CHG0045812 approved this activity.",
    ]
    assert view["gate"].startswith("Gate: APPROVE.")
    assert view["provider_host"] == "api.deepseek.com"
    assert view["rejected"] == [
        {
            "claim_id": "c3",
            "statement": "Change CHG0045812 approved this activity.",
            "reason": "Authorization is not checked in this demo.",
            "row_id": "",
        }
    ]
    assert view["evidence_claim_ids"] == ["c1", "c2"]
