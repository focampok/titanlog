"""P0 detectors and one-incident compression on the two OTRF files."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from correlate import correlate
from detectors import dangerous_access, detect
from ingest import load_dir
from titanlog.adapters.otrf_sysmon import OtrfSysmonAdapter
from titanlog.schema import Event

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "otrf"
COMSVCS = next(DATA.glob("psh_lsass_memory_dump_comsvcs*.json"))
PSEXEC = next(DATA.glob("empire_psexec_dcerpc_tcp_svcctl*.json"))


def _event(**overrides: object) -> Event:
    payload: dict[str, object] = {
        "row_id": "row",
        "event_code": 1,
        "source_file": "fixture.json",
        "raw": {},
    }
    payload.update(overrides)
    return Event(**payload)  # type: ignore[arg-type]


def test_dangerous_access_requires_vm_read_and_query() -> None:
    assert dangerous_access("0x1410") is True
    assert dangerous_access("0x1fffff") is True
    assert dangerous_access("0x1000") is False
    assert dangerous_access("0x10") is False


def test_encoding_flag_is_not_encoded_powershell() -> None:
    event = _event(process_command_line="powershell.exe -Encoding UTF8 -Command Get-Date")
    assert detect([event]) == []


def test_comsvcs_detectors() -> None:
    events, _ = OtrfSysmonAdapter().to_events(COMSVCS)
    counts = Counter(alert.detector for alert in detect(events))
    assert counts["lsass_comsvcs"] == 2
    assert counts["lsass_access_high"] == 2
    assert "encoded_powershell" not in counts
    assert "service_updater" not in counts
    assert {alert.event_code for alert in detect(events) if alert.detector == "lsass_comsvcs"} == {
        1,
        4688,
    }


def test_psexec_detectors() -> None:
    events, _ = OtrfSysmonAdapter().to_events(PSEXEC)
    counts = Counter(alert.detector for alert in detect(events))
    assert counts["encoded_powershell"] == 6
    assert counts["service_updater"] == 2
    assert "lsass_comsvcs" not in counts
    assert "lsass_access_high" not in counts


def test_p0_files_compress_to_one_incident() -> None:
    frame = load_dir(DATA)
    alerts = detect(frame)
    incident = correlate(frame, alerts)
    assert incident.compression.events == len(frame) == 4532
    assert incident.compression.alerts == len(alerts) == 12
    assert incident.compression.incidents == 1
    assert incident.compression.label() == "4532 → 12 → 1"
    assert "workstation5" in incident.hosts
    assert "workstation6" in incident.hosts
    assert any(user and "wardog" in user.casefold() for user in incident.users)
    assert incident.window_start is not None
    assert incident.window_end is not None
    assert incident.window_start < incident.window_end


def test_ui_detect_shows_compression() -> None:
    from streamlit.testing.v1 import AppTest

    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60)
    app.run()
    detect_button = next(button for button in app.button if button.label == "Detect")
    detect_button.click().run()
    assert not app.exception
    text = " ".join(item.value for item in app.markdown)
    assert "4532 → 12 → 1" in text
