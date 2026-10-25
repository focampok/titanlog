"""The public landing stays a product page, without the personal footer."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LANDING = ROOT / "pitch" / "index.html"


def test_landing_drops_personal_footer_and_keeps_measured_copy() -> None:
    text = LANDING.read_text(encoding="utf-8")
    visible = re.sub(r'src="data:[^"]*"', "", text)
    assert "info-titan-log" not in visible
    assert "https://focampo.com" not in visible
    assert "Francisco Ocampo" not in visible
    assert "https://titan-log.focampo.com" in visible
    assert "Any AI SOC" in visible
    assert "Cualquier SOC con IA" in visible
    assert 'data-es="SIMULADO"' in visible
    assert "~35 min saved per incident (ESTIMATE:" in visible
    assert text.count('class="stack"') == 2
