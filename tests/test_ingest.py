"""Ingest skeleton: real comsvcs file plus pure mapping checks."""

from __future__ import annotations

from pathlib import Path

from ingest import load_dir
from titanlog.adapters.otrf_sysmon import (
    OtrfSysmonAdapter,
    event_from_record,
    stable_row_id,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "otrf"
COMSVCS = next(DATA.glob("psh_lsass_memory_dump_comsvcs*.json"))


def test_comsvcs_loads_with_unique_int_codes() -> None:
    events, report = OtrfSysmonAdapter().to_events(COMSVCS)
    assert len(events) > 0
    assert report.parsed == len(events)
    assert report.skipped == 0
    assert len({event.row_id for event in events}) == len(events)
    assert all(isinstance(event.event_code, int) for event in events)

    again, _ = OtrfSysmonAdapter().to_events(COMSVCS)
    assert [event.row_id for event in again] == [event.row_id for event in events]


def test_comsvcs_minidump_row_exports_ecs() -> None:
    events, _ = OtrfSysmonAdapter().to_events(COMSVCS)
    hit = next(
        event
        for event in events
        if event.event_code == 1
        and event.process_command_line
        and "MiniDump" in event.process_command_line
    )
    assert hit.host_name == "WORKSTATION5"
    assert hit.process_executable == r"C:\Windows\System32\rundll32.exe"
    assert hit.user_name == r"WORKSTATION5\wardog"
    ecs = hit.to_ecs()
    assert ecs["event.code"] == 1
    assert isinstance(ecs["event.code"], int)
    assert ecs["host.name"] == "WORKSTATION5"
    assert ecs["process.command_line"]
    assert ecs["@timestamp"]
    assert isinstance(ecs["raw"], dict)


def test_row_id_depends_on_source_and_line() -> None:
    assert stable_row_id("a.json", 1) == stable_row_id("a.json", 1)
    assert stable_row_id("a.json", 1) != stable_row_id("a.json", 2)
    assert stable_row_id("a.json", 1) != stable_row_id("b.json", 1)


def test_service_path_fallback_and_user_order() -> None:
    sysmon = event_from_record(
        {
            "EventID": "10",
            "Hostname": "WORKSTATION5",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1010",
            "UtcTime": "2020-10-18 23:50:09.088",
            "User": "-",
            "SubjectUserName": "wardog",
        },
        source_file="fixture.json",
        line_no=4,
    )
    assert sysmon is not None
    assert sysmon.event_code == 10
    assert sysmon.user_name == "wardog"
    assert sysmon.granted_access == "0x1010"
    assert sysmon.target_process_executable.endswith("lsass.exe")
    assert sysmon.row_id == stable_row_id("fixture.json", 4)

    service = event_from_record(
        {
            "EventID": 7045,
            "Hostname": "WORKSTATION6",
            "ServiceName": "Updater",
            "ImagePath": r"%COMSPEC% /C powershell",
        },
        source_file="fixture.json",
        line_no=5,
    )
    assert service is not None
    assert service.service_name == "Updater"
    assert service.service_path.startswith("%COMSPEC%")

    preferred = event_from_record(
        {
            "EventID": 4697,
            "ServiceName": "Updater",
            "ServiceFileName": r"%COMSPEC% /C start",
            "ImagePath": r"C:\other.exe",
            "@timestamp": "2020-09-20T16:16:58.214Z",
        },
        source_file="fixture.json",
        line_no=6,
    )
    assert preferred is not None
    assert preferred.service_path == r"%COMSPEC% /C start"
    assert str(preferred.to_ecs()["@timestamp"]).endswith("+00:00")


def test_load_dir_keeps_comsvcs_rows() -> None:
    frame = load_dir(DATA)
    comsvcs = frame[frame["source_file"] == COMSVCS.name]
    assert len(comsvcs) > 0
    assert comsvcs["row_id"].is_unique
    assert list(frame.columns)[:2] == ["row_id", "ts"]
    assert all(isinstance(code, int) for code in comsvcs["event_code"])
