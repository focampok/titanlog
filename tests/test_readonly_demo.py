"""Public-demo path. No model calls."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORGED = ROOT / "demo" / "forged_incident.jsonl"


def test_readonly_demo_clicks_every_tab_and_the_forged_file(monkeypatch) -> None:
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("DEMO_READONLY", "1")
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    def _refuse(*_args, **_kwargs):
        raise AssertionError("the read-only demo must not call the model")

    monkeypatch.setattr("agents.investigate", _refuse)
    monkeypatch.setattr("agents._default_complete", _refuse)
    monkeypatch.setattr("titanlog.triage", _refuse)

    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=120)
    app.run()
    assert not app.exception

    labels = [tab.label for tab in app.tabs]
    assert labels == ["Incident", "Evidence", "Attack on the AI", "About"]
    text = _text(app)
    assert "Public demo — cached results; no live LLM" in text
    assert "REAL" in text
    assert "SIMULATED" in text
    assert "T1003.001" in text
    button_labels = [button.label for button in app.button] + [
        button.label for button in app.sidebar.button
    ]
    assert "Investigate with the configured model" not in button_labels
    assert "Load demo: forged incident" in button_labels

    forged = next(button for button in app.sidebar.button if button.label == "Load demo: forged incident")
    forged.click().run()
    assert not app.exception
    forged_text = _text(app)
    assert "Quarantined: 2" in forged_text
    assert "Incident still detected." in forged_text
    assert "⚠ SIMULATED" in forged_text

    app.file_uploader[0].upload(FORGED.name, FORGED.read_bytes()).run()
    assert not app.exception
    upload_text = _text(app)
    assert "Parsed" in upload_text or "Insufficient evidence" in upload_text or "known pattern" in upload_text.lower() or "A known pattern" in upload_text


def _text(app) -> str:
    chunks: list[str] = []
    for group in (
        app.markdown,
        app.text,
        app.caption,
        app.info,
        app.warning,
        app.success,
        app.error,
        app.metric,
    ):
        for item in group:
            value = getattr(item, "value", None)
            label = getattr(item, "label", None)
            if value:
                chunks.append(str(value))
            if label:
                chunks.append(str(label))
    return "\n".join(chunks)
