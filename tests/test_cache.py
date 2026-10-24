"""Offline cache includes the AFCR summary. No live LLM calls."""

from __future__ import annotations

import json

from cache import load_run, save_run


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

    saved = save_run(
        {"model": "deepseek-flash", "event_counts": {"events": 4532}},
        cache_path=cache_path,
        summary_path=summary_path,
    )

    loaded = load_run(saved)
    assert loaded["event_counts"]["events"] == 4532
    assert loaded["afcr_summary"]["simulated"] is True
    assert loaded["afcr_summary"]["rows"][0]["afcr_trials"] == 10
