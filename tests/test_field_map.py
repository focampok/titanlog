"""YAML field map: alternate keys match OTRF, and the comsvcs row is normalized."""

from __future__ import annotations

from pathlib import Path

import orjson

from titanlog.adapters.generic_jsonl import GenericJsonlAdapter, event_from_record
from titanlog.adapters.otrf_sysmon import OtrfSysmonAdapter
from titanlog.schema import Event

ROOT = Path(__file__).resolve().parents[1]
COMSVCS = next((ROOT / "data" / "otrf").glob("psh_lsass_memory_dump_comsvcs*.json"))

_OTRF_ROWS = [
    {
        "EventID": 1,
        "Hostname": "WORKSTATION5.theshire.local",
        "SubjectUserName": "wardog",
        "CommandLine": r"rundll32.exe C:\windows\System32\comsvcs.dll MiniDump",
        "Image": r"C:\Windows\System32\rundll32.exe",
        "UtcTime": "2020-10-18 23:50:05.910",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
    },
    {
        "EventID": 11,
        "Hostname": r"lab\WORKSTATION5",
        "TargetFilename": r"C:\Windows\Temp\lsass.dmp",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1010",
        "@timestamp": "not-a-timestamp",
    },
    {
        "EventID": 7045,
        "Hostname": "WORKSTATION6.theshire.local",
        "ServiceName": "Updater",
        "ImagePath": r"%COMSPEC% /C powershell",
        "User": "pgustavo",
        "@timestamp": "2020-09-20T16:16:58.214Z",
        "Channel": "System",
    },
]

_CUSTOM_ROWS = [
    {
        "event_id": 1,
        "computer_name": "WORKSTATION5.theshire.local",
        "user": "wardog",
        "cmdline": r"rundll32.exe C:\windows\System32\comsvcs.dll MiniDump",
        "NewProcessName": r"C:\Windows\System32\rundll32.exe",
        "TimeCreated": "2020-10-18 23:50:05.910",
        "channel": "Microsoft-Windows-Sysmon/Operational",
    },
    {
        "event_id": "11",
        "host": r"lab\WORKSTATION5",
        "file_path": r"C:\Windows\Temp\lsass.dmp",
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "target_image": r"C:\Windows\System32\lsass.exe",
        "granted_access": "0x1010",
        "UtcTime": "not-a-timestamp",
    },
    {
        "event_id": "7045",
        "host": "WORKSTATION6.theshire.local",
        "service_name": "Updater",
        "ServiceFileName": r"%COMSPEC% /C powershell",
        "user": "pgustavo",
        "TimeCreated": "2020-09-20T16:16:58.214Z",
        "channel": "System",
    },
]


def _write(directory: Path, rows: list[dict]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "sample.jsonl"
    path.write_bytes(b"\n".join(orjson.dumps(row) for row in rows) + b"\n")
    return path


def _normalized(event: Event) -> dict:
    data = event.model_dump()
    data.pop("raw")
    return data


def test_custom_keys_match_otrf_adapter(tmp_path: Path) -> None:
    otrf_events, _ = OtrfSysmonAdapter().to_events(_write(tmp_path / "otrf", _OTRF_ROWS))
    custom_events, _ = GenericJsonlAdapter().to_events(
        _write(tmp_path / "custom", _CUSTOM_ROWS)
    )
    assert len(otrf_events) == 3
    assert [_normalized(event) for event in custom_events] == [
        _normalized(event) for event in otrf_events
    ]
    assert custom_events[0].raw != otrf_events[0].raw
    assert [event.host_key for event in otrf_events] == [
        "workstation5",
        "workstation5",
        "workstation6",
    ]
    assert all(event.has_attacker_controlled_field for event in otrf_events)
    assert all(isinstance(event.event_code, int) for event in custom_events)
    assert otrf_events[1].ts == "not-a-timestamp"
    assert str(otrf_events[2].to_ecs()["@timestamp"]).endswith("+00:00")


def test_both_adapters_agree_on_the_same_file() -> None:
    otrf_events, otrf_report = OtrfSysmonAdapter().to_events(COMSVCS)
    generic_events, generic_report = GenericJsonlAdapter().to_events(COMSVCS)
    assert [event.model_dump() for event in generic_events] == [
        event.model_dump() for event in otrf_events
    ]
    assert generic_report.parsed == otrf_report.parsed


def test_comsvcs_minidump_host_key_and_event_code() -> None:
    events, _ = OtrfSysmonAdapter().to_events(COMSVCS)
    hit = next(
        event
        for event in events
        if event.event_code == 1
        and event.user_name
        and "wardog" in event.user_name.casefold()
        and event.process_executable
        and "rundll32" in event.process_executable.casefold()
    )
    assert isinstance(hit.event_code, int)
    assert hit.event_code == 1
    assert hit.host_key == "workstation5"
    assert hit.has_attacker_controlled_field is True
    assert str(hit.to_ecs()["@timestamp"]).startswith("2020-10-18T23:50:05.910")


def test_quiet_row_is_not_attacker_controlled() -> None:
    event = event_from_record(
        {
            "EventID": 5,
            "Hostname": "WORKSTATION5.theshire.local",
            "CommandLine": "-",
            "TargetFilename": "",
            "ImagePath": None,
        },
        source_file="quiet.json",
        line_no=1,
    )
    assert event is not None
    assert event.host_key == "workstation5"
    assert event.has_attacker_controlled_field is False
