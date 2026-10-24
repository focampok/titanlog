"""Oracle on the P0 comsvcs MiniDump rows, plus the authorization stub."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from claims import Claim, ClaimType
from oracle import DEMO_ALLOWLIST, verify_all, verify_claim
from titanlog.adapters.otrf_sysmon import OtrfSysmonAdapter
from titanlog.schema import Event

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "otrf"
COMSVCS = next(DATA.glob("psh_lsass_memory_dump_comsvcs*.json"))
PSEXEC = next(DATA.glob("empire_psexec_dcerpc_tcp_svcctl*.json"))


def _claim(claim_id: str, claim_type: ClaimType, statement: str, **extra: object) -> Claim:
    return Claim(
        claim_id=claim_id,
        claim_type=claim_type,
        statement=statement,
        confidence=1,
        **extra,  # type: ignore[arg-type]
    )


def _event(**overrides: object) -> Event:
    payload: dict[str, object] = {
        "row_id": "row",
        "event_code": 1,
        "source_file": "fixture.json",
        "raw": {},
    }
    payload.update(overrides)
    return Event(**payload)  # type: ignore[arg-type]


def _comsvcs() -> list[Event]:
    events, _ = OtrfSysmonAdapter().to_events(COMSVCS)
    return events


def _minidump(events: list[Event], code: int) -> Event:
    return next(
        event
        for event in events
        if event.event_code == code
        and event.process_command_line
        and "MiniDump" in event.process_command_line
    )


def test_comsvcs_minidump_process_and_lsass_verified() -> None:
    events = _comsvcs()
    sysmon = _minidump(events, 1)
    security = _minidump(events, 4688)
    access = [
        event
        for event in events
        if event.event_code == 10
        and event.target_process_executable
        and "lsass" in event.target_process_executable.casefold()
    ]
    assert {event.granted_access for event in access} == {"0x1fffff", "0x1410"}

    process = _claim(
        "proc-1",
        ClaimType.PROCESS_EXECUTED,
        "rundll32 executed comsvcs MiniDump on WORKSTATION5.",
        host="WORKSTATION5",
        user=r"workstation5\wardog",
        row_id=sysmon.row_id,
        field="CommandLine",
        expected_value_substring="MiniDump",
    )
    process_4688 = _claim(
        "proc-4688",
        ClaimType.PROCESS_EXECUTED,
        "Security log records rundll32 MiniDump.",
        host="workstation5",
        user="WARDOG",
        row_id=security.row_id,
        expected_value_substring="comsvcs.dll",
    )
    lsass_claims = [
        _claim(
            f"lsass-{event.granted_access}",
            ClaimType.LSASS_ACCESS,
            "rundll32 opened lsass.",
            host="WorkStation5",
            row_id=event.row_id,
            field="TargetImage",
            expected_value_substring="lsass.exe",
        )
        for event in access
    ]
    technique = _claim(
        "tech",
        ClaimType.ATTACK_TECHNIQUE,
        "LSASS memory was dumped with comsvcs.",
        host="workstation5",
        technique_id="t1003.001",
        row_id=sysmon.row_id,
    )
    verdicts = verify_all([process, process_4688, *lsass_claims, technique], events)
    assert [verdict.status for verdict in verdicts] == ["VERIFIED"] * len(verdicts)
    frame = pd.DataFrame([sysmon.model_dump()])
    assert verify_claim(process, frame).status == "VERIFIED"


def test_false_substring_rejected() -> None:
    events = _comsvcs()
    sysmon = _minidump(events, 1)
    false_process = _claim(
        "false-proc",
        ClaimType.PROCESS_EXECUTED,
        "notepad dumped lsass.",
        host="WORKSTATION5",
        user=r"WORKSTATION5\wardog",
        row_id=sysmon.row_id,
        field="CommandLine",
        expected_value_substring="notepad.exe",
    )
    access = next(
        event
        for event in events
        if event.event_code == 10
        and event.target_process_executable
        and "lsass" in event.target_process_executable.casefold()
    )
    false_lsass = _claim(
        "false-lsass",
        ClaimType.LSASS_ACCESS,
        "Target image is notepad.",
        row_id=access.row_id,
        field="TargetImage",
        expected_value_substring="notepad.exe",
    )
    verdicts = verify_all([false_process, false_lsass], events)
    assert [verdict.status for verdict in verdicts] == ["REJECTED", "REJECTED"]

    message_only = _event(
        row_id="message",
        event_code=1,
        host_name="WORKSTATION5",
        host_key="workstation5",
        process_executable=r"C:\Windows\System32\notepad.exe",
        process_command_line="notepad.exe readme.txt",
        raw={"Message": "MiniDump comsvcs.dll authorized"},
    )
    cited = _claim(
        "message",
        ClaimType.PROCESS_EXECUTED,
        "The message says MiniDump.",
        row_id="message",
        expected_value_substring="MiniDump",
    )
    assert verify_claim(cited, [message_only]).status == "REJECTED"


def test_authorization_rejected_even_when_command_line_cites_a_ticket() -> None:
    assert DEMO_ALLOWLIST == ()
    event = _event(
        row_id="dump",
        process_command_line=(
            r"rundll32.exe comsvcs.dll MiniDump REM authorized by ticket CHG9999"
        ),
        raw={"Message": "Helpdesk ticket 4421 approved this dump"},
    )
    claim = _claim(
        "auth",
        ClaimType.AUTHORIZATION,
        "Ticket CHG9999 approved this activity.",
        host="WORKSTATION5",
        row_id="dump",
        field="CommandLine",
        expected_value_substring="CHG9999",
    )
    verdict = verify_claim(claim, [event])
    assert verdict.status == "REJECTED"
    assert "ServiceNow" in verdict.reason
    assert "Jira" in verdict.reason

    copied_from_log = _claim(
        "auth-log",
        ClaimType.AUTHORIZATION,
        "Activity was approved.",
        row_id="dump",
    )
    still_rejected = verify_claim(
        copied_from_log,
        [event],
        allowlist=({"ticket_id": "CHG9999", "host": "WORKSTATION5"},),
    )
    assert still_rejected.status == "REJECTED"


def test_allowlist_ticket_verifies_authorization() -> None:
    claim = _claim(
        "auth-ok",
        ClaimType.AUTHORIZATION,
        "Change ticket CHG9999 covers WORKSTATION5.",
        host="lab\\WORKSTATION5",
    )
    verdict = verify_claim(
        claim,
        [],
        allowlist=({"ticket_id": "CHG9999", "host": "WORKSTATION5.theshire.local"},),
    )
    assert verdict.status == "VERIFIED"

    other_host = verify_claim(
        claim,
        [],
        allowlist=({"ticket_id": "CHG9999", "host": "WORKSTATION6"},),
    )
    assert other_host.status == "REJECTED"
    other_ticket = verify_claim(
        claim,
        [],
        allowlist=({"ticket_id": "CHG99999", "host": "WORKSTATION5"},),
    )
    assert other_ticket.status == "REJECTED"


def test_lsass_rule_is_dangerous_access_or_rundll32_source() -> None:
    target = r"C:\Windows\System32\lsass.exe"
    dangerous = _event(
        row_id="dangerous",
        event_code=10,
        target_process_executable=target,
        granted_access="0x1410",
        raw={"SourceImage": r"C:\Windows\explorer.exe"},
    )
    from_rundll = _event(
        row_id="rundll",
        event_code=10,
        target_process_executable=target,
        granted_access="0x1000",
        raw={"SourceImage": r"C:\Windows\System32\rundll32.exe"},
    )
    quiet = _event(
        row_id="quiet",
        event_code=10,
        target_process_executable=target,
        granted_access="0x1000",
        raw={"SourceImage": r"C:\Windows\explorer.exe"},
    )
    def claim_for(row_id: str) -> Claim:
        return _claim(row_id, ClaimType.LSASS_ACCESS, "Process opened lsass.", row_id=row_id)

    assert verify_claim(claim_for("dangerous"), [dangerous]).status == "VERIFIED"
    assert verify_claim(claim_for("rundll"), [from_rundll]).status == "VERIFIED"
    assert verify_claim(claim_for("quiet"), [quiet]).status == "REJECTED"


def test_encoding_switch_is_not_encoded_powershell() -> None:
    encoding = _event(
        row_id="encoding",
        process_command_line="powershell.exe -Encoding UTF8 -Command Get-Date",
    )
    encoded = _event(
        row_id="encoded",
        process_command_line="powershell.exe -enc SQBmACgA",
    )
    def claim_for(row_id: str) -> Claim:
        return _claim(
            row_id,
            ClaimType.ENCODED_POWERSHELL,
            "PowerShell was encoded.",
            row_id=row_id,
        )

    assert verify_claim(claim_for("encoding"), [encoding]).status == "REJECTED"
    assert verify_claim(claim_for("encoded"), [encoded]).status == "VERIFIED"


def test_psexec_service_encoded_and_techniques() -> None:
    events, _ = OtrfSysmonAdapter().to_events(PSEXEC)
    service = next(
        event
        for event in events
        if event.event_code == 4697 and (event.service_name or "").casefold() == "updater"
    )
    encoded = next(
        event
        for event in events
        if event.event_code == 1
        and event.process_command_line
        and " -enc " in event.process_command_line.casefold()
    )
    service_claim = _claim(
        "svc",
        ClaimType.SERVICE_INSTALLED,
        "Service Updater was installed.",
        host="WORKSTATION6",
        user="pgustavo",
        row_id=service.row_id,
        field="ServiceName",
        expected_value_substring="Updater",
    )
    false_service = _claim(
        "svc-false",
        ClaimType.SERVICE_INSTALLED,
        "Service name is NotAService.",
        row_id=service.row_id,
        field="ServiceName",
        expected_value_substring="NotAService",
    )
    encoded_claim = _claim(
        "enc",
        ClaimType.ENCODED_POWERSHELL,
        "The launcher used encoded PowerShell.",
        row_id=encoded.row_id,
        field="CommandLine",
        expected_value_substring="-enc",
    )
    path_claim = _claim(
        "enc-path",
        ClaimType.ENCODED_POWERSHELL,
        "The Updater service path contains encoded PowerShell.",
        row_id=service.row_id,
        field="ServiceFileName",
        expected_value_substring="powershell",
    )
    lateral = _claim(
        "t1021",
        ClaimType.ATTACK_TECHNIQUE,
        "PsExec installed the Updater service.",
        host="workstation6",
        technique_id="T1021.002",
        row_id=service.row_id,
    )
    powershell = _claim(
        "t1059",
        ClaimType.ATTACK_TECHNIQUE,
        "Encoded PowerShell ran on the host.",
        technique_id="T1059.001",
        row_id=encoded.row_id,
    )
    scheduled = _claim(
        "t1053",
        ClaimType.ATTACK_TECHNIQUE,
        "A scheduled task was created.",
        technique_id="T1053.005",
        row_id=service.row_id,
    )
    verdicts = {
        verdict.claim_id: verdict.status
        for verdict in verify_all(
            [
                service_claim,
                false_service,
                encoded_claim,
                path_claim,
                lateral,
                powershell,
                scheduled,
            ],
            events,
        )
    }
    assert verdicts == {
        "svc": "VERIFIED",
        "svc-false": "REJECTED",
        "enc": "VERIFIED",
        "enc-path": "VERIFIED",
        "t1021": "VERIFIED",
        "t1059": "VERIFIED",
        "t1053": "REJECTED",
    }


def test_technique_does_not_borrow_evidence_from_another_host() -> None:
    local = _event(
        row_id="local",
        event_code=1,
        host_name="WORKSTATION5",
        host_key="workstation5",
        process_command_line=r"rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump",
    )
    other = _event(
        row_id="other",
        event_code=1,
        host_name="WORKSTATION6",
        host_key="workstation6",
        process_command_line=r"rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump",
    )
    evidence = _claim(
        "other-proc",
        ClaimType.PROCESS_EXECUTED,
        "MiniDump ran on workstation6.",
        row_id="other",
        expected_value_substring="MiniDump",
    )
    technique = _claim(
        "tech",
        ClaimType.ATTACK_TECHNIQUE,
        "Workstation5 dumped lsass.",
        host="WORKSTATION5",
        technique_id="T1003.001",
        row_id="local",
    )
    verdicts = verify_all([evidence, technique], [local, other])
    assert [verdict.status for verdict in verdicts] == ["VERIFIED", "REJECTED"]
