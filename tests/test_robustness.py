"""Robust ingest: one tiny fixture per failure mode, plus the demo sample."""

from __future__ import annotations

from pathlib import Path

import orjson

from ingest import ingest_file

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "samples" / "corrupted.jsonl"
_LIMIT = 64 * 1024


def _ingest(tmp_path: Path, name: str, body: bytes):
    path = tmp_path / name
    path.write_bytes(body)
    return ingest_file(path, quarantine_dir=tmp_path / "quarantine")


def _line(record: dict) -> bytes:
    return orjson.dumps(record)


def test_malformed_json_line(tmp_path: Path) -> None:
    good = _line(
        {
            "EventID": 1,
            "Hostname": "LAB",
            "Image": r"C:\Windows\System32\notepad.exe",
            "CommandLine": "notepad.exe",
        }
    )
    frame, report = _ingest(tmp_path, "bad.jsonl", good + b"\n{not json\n")
    assert report.parsed == 1
    assert report.skipped_by_reason["malformed_json"] == 1
    assert len(frame) == 1
    blob = Path(report.quarantined_path[0]).read_bytes()
    assert b"{not json" in blob
    assert report.status == "insufficient_evidence"


def test_missing_fields(tmp_path: Path) -> None:
    body = _line({"Hostname": "WORKSTATION5", "Image": r"C:\Windows\notepad.exe"}) + b"\n"
    frame, report = _ingest(tmp_path, "missing.jsonl", body)
    assert frame.empty
    assert report.parsed == 0
    assert report.skipped_by_reason["missing_fields"] == 1
    assert report.status == "insufficient_evidence"
    assert Path(report.quarantined_path[0]).name.endswith(".missing_fields.jsonl")


def test_unknown_event_id(tmp_path: Path) -> None:
    body = _line({"EventID": 424242, "Hostname": "WORKSTATION5"}) + b"\n"
    frame, report = _ingest(tmp_path, "unknown.jsonl", body)
    assert frame.empty
    assert report.skipped_by_reason["unknown_event_id"] == 1
    assert report.unknown_event_ids == [424242]
    assert report.status == "insufficient_evidence"


def test_empty_file(tmp_path: Path) -> None:
    frame, report = _ingest(tmp_path, "empty.jsonl", b"")
    assert frame.empty
    assert report.parsed == 0
    assert report.skipped_by_reason["empty_file"] == 1
    assert report.skipped == 1
    assert report.status == "insufficient_evidence"
    assert Path(report.quarantined_path[0]).is_file()


def test_huge_field_is_truncated_and_flagged(tmp_path: Path) -> None:
    command = "A" * (_LIMIT + 32)
    body = _line(
        {
            "EventID": 1,
            "Hostname": "LAB",
            "Image": r"C:\Windows\System32\notepad.exe",
            "CommandLine": command,
        }
    )
    frame, report = _ingest(tmp_path, "huge.jsonl", body + b"\n")
    assert report.parsed == 1
    assert report.skipped_by_reason["huge_field"] == 1
    assert report.skipped == 0
    assert bool(frame.loc[0, "truncated"]) is True
    kept = frame.loc[0, "process_command_line"]
    assert len(kept.encode("utf-8")) <= _LIMIT
    assert len(kept) < len(command)
    original = Path(report.quarantined_path[0]).read_bytes()
    assert command.encode() in original
    assert report.status == "insufficient_evidence"


def test_non_windows_json(tmp_path: Path) -> None:
    body = _line({"service": "nginx", "msg": "started"}) + b"\n"
    frame, report = _ingest(tmp_path, "nginx.jsonl", body)
    assert frame.empty
    assert report.skipped_by_reason["non_windows"] == 1
    assert report.status == "insufficient_evidence"


def test_json_array_instead_of_jsonl(tmp_path: Path) -> None:
    body = orjson.dumps(
        [
            {"EventID": 1, "Hostname": "LAB", "Image": r"C:\Windows\notepad.exe"},
            {"EventID": 1, "Hostname": "LAB2"},
        ]
    )
    frame, report = _ingest(tmp_path, "array.json", body)
    assert frame.empty
    assert report.parsed == 0
    assert report.skipped_by_reason["json_array"] == 1
    assert Path(report.quarantined_path[0]).read_bytes().lstrip().startswith(b"[")
    assert report.status == "insufficient_evidence"


def test_known_pattern_is_not_a_verdict(tmp_path: Path) -> None:
    body = _line(
        {
            "EventID": 1,
            "Hostname": "WORKSTATION5",
            "Image": r"C:\Windows\System32\rundll32.exe",
            "CommandLine": (
                r"C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll MiniDump"
            ),
        }
    )
    frame, report = _ingest(tmp_path, "minidump.jsonl", body + b"\n")
    assert report.parsed == 1
    assert report.skipped == 0
    assert len(frame) == 1
    assert report.status == "known_pattern"


def test_corrupted_sample_routes_to_human(tmp_path: Path) -> None:
    _frame, report = ingest_file(SAMPLE, quarantine_dir=tmp_path / "quarantine")
    assert report.parsed >= 1
    assert report.skipped_by_reason["malformed_json"] >= 1
    assert report.skipped_by_reason["missing_fields"] >= 1
    assert report.skipped_by_reason["unknown_event_id"] >= 1
    assert report.skipped_by_reason["non_windows"] >= 1
    assert report.skipped_by_reason["huge_field"] >= 1
    assert report.unknown_event_ids == [424242]
    assert report.status == "insufficient_evidence"
    assert report.quarantined_path


def test_upload_shows_insufficient_evidence_without_traceback() -> None:
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.run()
    assert not app.exception
    app.file_uploader[0].upload("corrupted.jsonl", SAMPLE.read_bytes()).run()
    assert not app.exception
    text = " ".join(item.value for item in app.warning)
    assert "Insufficient evidence — sent to human" in text
