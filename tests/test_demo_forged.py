"""Forged-incident demo. No model calls."""

from __future__ import annotations

import os
from pathlib import Path

import orjson

from demo_forged import FORGED_PATH, PAYLOAD, SIMULATED_LABEL, review_forged
from ingest import ingest_file

ROOT = Path(__file__).resolve().parents[1]


def test_forged_file_quarantines_two_lines_and_keeps_the_incident(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_READONLY", "1")

    def _refuse(*_args, **_kwargs):
        raise AssertionError("the forged demo must not call the model")

    monkeypatch.setattr("agents.investigate", _refuse)
    result = review_forged(quarantine_dir=tmp_path)
    assert result.quarantined == 2
    assert result.reasons["malformed_json"] == 1
    assert result.reasons["impossible_timestamp"] == 1
    assert result.insufficient_lines == 1
    assert "insufficient_evidence" not in {path.name.split(".")[-2] for path in tmp_path.iterdir()}
    names = {path.name for path in tmp_path.iterdir()}
    assert any(name.endswith(".malformed_json.jsonl") for name in names)
    assert any(name.endswith(".impossible_timestamp.jsonl") for name in names)
    assert len(result.injections) == 2
    assert all(PAYLOAD in line for line in result.injections)
    assert result.incident_detected is True
    assert result.alert_count >= 1
    assert result.close is False
    assert result.injection_verdicts
    assert {label for label, _statement in result.injection_verdicts} <= {"REFUTED", "INSUFFICIENT"}


def test_forged_file_flags_two_simulated_lines() -> None:
    lines = [line for line in FORGED_PATH.read_bytes().splitlines() if line.strip()]
    assert 20 <= len(lines) <= 40
    labeled = []
    for raw in lines:
        try:
            record = orjson.loads(raw)
        except orjson.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("_titan_label") == SIMULATED_LABEL:
            labeled.append(record)
    assert len(labeled) == 2
    assert PAYLOAD in str(labeled[0].get("CommandLine"))
    assert PAYLOAD in str(labeled[1].get("Message"))


def test_impossible_timestamp_is_quarantined_and_ambiguous_line_is_not(tmp_path: Path) -> None:
    body = b"\n".join(
        [
            orjson.dumps(
                {
                    "EventID": 1,
                    "Hostname": "WORKSTATION5",
                    "UtcTime": "2020-13-40T99:99:99",
                    "CommandLine": "notepad.exe",
                }
            ),
            orjson.dumps({"Channel": "Security", "Image": r"C:\Windows\System32\svchost.exe"}),
            b"{not json",
        ]
    )
    path = tmp_path / "mixed.jsonl"
    path.write_bytes(body + b"\n")
    frame, report = ingest_file(path, quarantine_dir=tmp_path / "quarantine")
    assert frame.empty or "notepad.exe" not in set(frame["process_command_line"].fillna(""))
    assert report.skipped_by_reason["impossible_timestamp"] == 1
    assert report.skipped_by_reason["insufficient_evidence"] == 1
    assert report.skipped_by_reason["malformed_json"] == 1
    names = [Path(item).name for item in report.quarantined_path]
    assert any(name.endswith(".impossible_timestamp.jsonl") for name in names)
    assert any(name.endswith(".malformed_json.jsonl") for name in names)
    assert not any("insufficient_evidence" in name for name in names)


def test_load_demo_button_runs_without_a_model_key(monkeypatch) -> None:
    from streamlit.testing.v1 import AppTest

    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_READONLY", "1")
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=90)
    app.run()
    assert not app.exception
    sidebar_buttons = [button for button in app.sidebar.button if button.label == "Load demo: forged incident"]
    assert sidebar_buttons
    sidebar_buttons[0].click().run()
    assert not app.exception
    text = " ".join(
        str(item.value)
        for group in (app.warning, app.markdown, app.text, app.caption)
        for item in group
        if getattr(item, "value", None)
    )
    assert "Quarantined: 2" in text
    assert text.count("⚠ SIMULATED") == 2
    assert "Incident still detected" in text
    assert "close=false" in text
    assert "REFUTED" in text or "INSUFFICIENT" in text
    assert os.environ.get("LLM_API_KEY", "") == ""
