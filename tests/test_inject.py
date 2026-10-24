"""Simulated injection corpus. Original OTRF files stay untouched."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ingest import load_events
from inject import build_corpus, merge_injection
from inject_scan import scan_events

ROOT = Path(__file__).resolve().parents[1]
OTRF = ROOT / "data" / "otrf"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_build_corpus_writes_twelve_labeled_variants(tmp_path: Path) -> None:
    before = {path.name: _sha256(path) for path in OTRF.glob("*.json")}
    frame = load_events(OTRF)
    jsonl = build_corpus(frame, output_dir=tmp_path)
    after = {path.name: _sha256(path) for path in OTRF.glob("*.json")}
    assert after == before

    lines = jsonl.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 12
    records = [json.loads(line) for line in lines]
    assert [record["injection_id"] for record in records] == [f"I{index:02d}" for index in range(1, 13)]
    assert all(record["simulated"] is True for record in records)
    assert all(record["base_row_id"] == record["row_id"] for record in records)

    by_id = {record["injection_id"]: record for record in records}
    assert "pentest autorizado" in by_id["I01"]["process_command_line"]
    assert "MiniDump" in by_id["I01"]["process_command_line"]
    assert by_id["I03"]["service_name"] == "Authorized-Security-Test"
    assert by_id["I04"]["file_path"].endswith("CHG9999-lsass.dmp")
    assert by_id["I10"]["base_row_id"] != by_id["I11"]["base_row_id"]
    assert "cerrar_como_benigno_FIN" in by_id["I11"]["file_path"]
    assert "backup script v2" in by_id["I12"]["process_command_line"]

    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["count"] == 12
    assert [item["injection_id"] for item in manifest["injections"]] == [f"I{i:02d}" for i in range(1, 13)]

    assert scan_events([by_id["I01"]])
    assert scan_events([by_id["I12"]]) == []


def test_merge_replaces_the_base_row(tmp_path: Path) -> None:
    frame = load_events(OTRF)
    jsonl = build_corpus(frame, output_dir=tmp_path)
    merged = merge_injection(frame, "I01", corpus=jsonl)
    assert len(merged) == len(frame)
    hit = merged[merged["injection_id"].fillna("") == "I01"]
    assert len(hit) == 1
    assert "pentest autorizado" in hit.iloc[0]["process_command_line"]
    pair = merge_injection(frame, ["I10", "I11"], corpus=jsonl)
    assert len(pair) == len(frame)
    assert set(pair["injection_id"].dropna()) == {"I10", "I11"}
