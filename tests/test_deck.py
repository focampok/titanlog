"""The offline pitch deck stays in sync with the measured result files."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

from console import analyst_minutes_estimate

ROOT = Path(__file__).resolve().parents[1]
DECK = ROOT / "pitch" / "deck.html"
ALLOWED_URLS = [
    "https://github.com/focampok/titanlog",
    "https://titan-log.focampo.com",
]
NS = "http://www.w3.org/1999/xhtml"


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.slides = 0
        self.cells: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key: value or "" for key, value in attrs}
        if tag == "section" and "slide" in values.get("class", ""):
            self.slides += 1
        for key in ("href", "src"):
            if values.get(key):
                self.urls.append(values[key])
        if tag == "td" and values.get("data-metric"):
            self.cells.append(values)


def test_pitch_deck_parses_and_matches_measured_counts() -> None:
    text = DECK.read_text(encoding="utf-8")
    root = ET.fromstring(text[text.index("<html") :])
    slides = [node for node in root.iter(f"{{{NS}}}section") if "slide" in (node.get("class") or "")]
    assert len(slides) == 8
    titles = [slide.find(f"{{{NS}}}h1").get("data-en") for slide in slides]
    assert titles[-2:] == ["Roadmap", "Glossary"]

    parsed = _Links()
    parsed.feed(text)
    assert parsed.slides == 8
    assert parsed.urls == ALLOWED_URLS
    assert "Where it fits" in text
    assert "Dónde encaja" in text
    assert "AI-native SOC architecture" in text
    assert "Arquitectura SOC nativa de IA" in text
    assert "A un prompt se le puede convencer. A un verificador, no." in text
    assert "Next steps. Not implemented." in text
    assert "Próximos pasos" in text
    assert "Roadmap, not built." in text
    assert "Model Context Protocol" in text
    assert "<img" not in text
    leftover = (
        text.replace("http://www.w3.org/2000/svg", "")
        .replace("http://www.w3.org/1999/xhtml", "")
    )
    assert "http://" not in leftover
    assert "fonts.googleapis" not in text

    summary = json.loads((ROOT / "results" / "afcr_summary.json").read_text(encoding="utf-8"))
    found = {
        (cell["data-model"], cell["data-arm"], cell["data-metric"]): cell for cell in parsed.cells
    }
    for row in summary["rows"]:
        for metric, closed_key, trials_key in (
            ("any_close", "any_close_all_18_closed", "any_close_all_18_trials"),
            ("influence", "influenced", "influence_trials"),
        ):
            cell = found[(row["model_id"], row["arm"], metric)]
            assert cell["data-en"] == f"{row[closed_key]} of {row[trials_key]}"
            assert cell["data-es"] == f"{row[closed_key]} de {row[trials_key]}"

    counts = json.loads((ROOT / "results" / "run_cache.json").read_text(encoding="utf-8"))["event_counts"]
    assert f'data-events="{counts["events"]}"' in text
    assert f'data-alerts="{counts["alerts"]}"' in text
    assert f'data-incidents="{counts["incidents"]}"' in text
    label = analyst_minutes_estimate()
    spanish = label.replace(
        "min saved per incident", "min ahorrados por incidente"
    ).replace(
        "with Titan.Log; assumptions, not measured",
        "con Titan.Log; supuestos, no medido",
    )
    writeup = (ROOT / "WRITEUP.md").read_text(encoding="utf-8")
    assert label in text
    assert spanish in text
    assert "ESTIMATE" in spanish
    assert label in writeup
    assert "[pending]" not in text
    assert "[pending]" not in writeup
