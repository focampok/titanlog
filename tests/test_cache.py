"""Offline cache includes the AFCR summary. No live LLM calls."""

from __future__ import annotations

import json

from cache import VERSION, load_run, payload_from_incident, save_run
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
