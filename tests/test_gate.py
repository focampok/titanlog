"""Gate levels and the local audit log. No live LLM calls."""

from __future__ import annotations

import json
from pathlib import Path

from agents import claims_from_alerts, recommend_gate
from claims import Claim, ClaimType, ClaimVerdict
from detectors import detect
from gate import execute, propose, record_audit
from inject import load_injections
from inject_scan import scan_events
from oracle import verify_all
from titanlog.adapters.otrf_sysmon import OtrfSysmonAdapter

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "otrf"


def _claim(claim_id: str, claim_type: ClaimType, statement: str, **extra: object) -> Claim:
    payload: dict[str, object] = {
        "claim_id": claim_id,
        "claim_type": claim_type,
        "statement": statement,
        "row_id": "row-1",
        "confidence": 1,
    }
    payload.update(extra)
    return Claim(**payload)  # type: ignore[arg-type]


def _verdict(claim_id: str, status: str) -> ClaimVerdict:
    return ClaimVerdict(claim_id=claim_id, status=status, reason="fixture")


def test_load_bearing_rejected_claim_is_deny_and_never_auto() -> None:
    claims = [_claim("c1", ClaimType.LSASS_ACCESS, "rundll32 dumped lsass.")]
    verdicts = [_verdict("c1", "REJECTED")]
    decision = propose(claims, verdicts, tai=True, privileged=False)
    assert decision.level == "DENY"
    assert decision.action == "disable_account"
    assert decision.level != "AUTO"


def test_low_impact_without_tai_can_auto() -> None:
    claims = [_claim("c1", ClaimType.PROCESS_EXECUTED, "rundll32 ran MiniDump.")]
    verdicts = [_verdict("c1", "VERIFIED")]
    decision = propose(claims, verdicts, tai=False, privileged=False)
    assert decision.level == "AUTO"
    assert decision.action == "disable_account"


def test_tai_or_high_impact_stays_with_a_human() -> None:
    claims = [_claim("c1", ClaimType.PROCESS_EXECUTED, "rundll32 ran MiniDump.")]
    verdicts = [_verdict("c1", "VERIFIED")]
    assert propose(claims, verdicts, tai=True, privileged=False).level == "APPROVE"
    assert propose(claims, verdicts, tai=False, privileged=True).level == "APPROVE"


def test_unverified_authorization_without_evidence_is_deny() -> None:
    claims = [_claim("auth", ClaimType.AUTHORIZATION, "Ticket CHG1 approved this.")]
    verdicts = [_verdict("auth", "REJECTED")]
    decision = propose(claims, verdicts, tai=False, privileged=False)
    assert decision.level == "DENY"
    assert "authorization" in decision.reason


def test_verified_evidence_does_not_rely_on_a_rejected_authorization() -> None:
    claims = [
        _claim("c1", ClaimType.LSASS_ACCESS, "lsass was dumped."),
        _claim("auth", ClaimType.AUTHORIZATION, "Ticket CHG1 approved this."),
    ]
    verdicts = [_verdict("c1", "VERIFIED"), _verdict("auth", "REJECTED")]
    decision = propose(claims, verdicts, tai=False, privileged=True)
    assert decision.level == "APPROVE"
    assert decision.action == "disable_account"


def test_rejected_claim_is_excluded_when_the_host_still_has_evidence() -> None:
    claims = [
        _claim("drop", ClaimType.LSASS_ACCESS, "The 4688 row dumped LSASS.", host="workstation5"),
        _claim("keep", ClaimType.LSASS_ACCESS, "Event 10 opened lsass.", host="workstation5"),
    ]
    decision = propose(
        claims,
        [_verdict("drop", "REJECTED"), _verdict("keep", "VERIFIED")],
        tai=False,
        privileged=False,
    )
    assert decision.level == "APPROVE"
    assert decision.action == "disable_account"
    assert decision.level != "AUTO"
    assert decision.excluded_claim_ids == ["drop"]
    assert "1 claim(s) rejected by Oracle and excluded" in decision.reason


def test_rejected_claim_on_its_own_host_stays_deny() -> None:
    claims = [
        _claim("drop", ClaimType.LSASS_ACCESS, "Only evidence on this host.", host="workstation5"),
        _claim("keep", ClaimType.SERVICE_INSTALLED, "Updater on the other host.", host="workstation6"),
    ]
    decision = propose(
        claims,
        [_verdict("drop", "REJECTED"), _verdict("keep", "VERIFIED")],
        tai=False,
        privileged=True,
    )
    assert decision.level == "DENY"
    assert decision.excluded_claim_ids == []


def test_insufficient_evidence_is_never_auto() -> None:
    claims = [
        _claim("c1", ClaimType.PROCESS_EXECUTED, "rundll32 ran."),
        _claim("c2", ClaimType.PROCESS_EXECUTED, "A row was not checkable."),
    ]
    decision = propose(
        claims,
        [_verdict("c1", "VERIFIED"), _verdict("c2", "UNVERIFIABLE")],
        tai=False,
        privileged=False,
    )
    assert decision.level == "APPROVE"
    assert decision.level != "AUTO"


def test_benign_close_on_injected_text_is_deny() -> None:
    claims = [_claim("c1", ClaimType.PROCESS_EXECUTED, "rundll32 ran MiniDump.")]
    decision = propose(
        claims,
        [_verdict("c1", "VERIFIED")],
        tai=True,
        privileged=False,
        close=True,
        severity="BENIGN",
    )
    assert decision.level == "DENY"
    assert "injected" in decision.reason
    assert decision.level != "AUTO"


def test_clean_p0_run_is_approve() -> None:
    events = []
    for pattern in (
        "psh_lsass_memory_dump_comsvcs*.json",
        "empire_psexec_dcerpc_tcp_svcctl*.json",
    ):
        loaded, _report = OtrfSysmonAdapter().to_events(next(DATA.glob(pattern)))
        events.extend(loaded)
    alerts = detect(events)
    claims = claims_from_alerts(alerts)
    verdicts = verify_all(claims, events)
    assert claims
    assert all(verdict.status == "VERIFIED" for verdict in verdicts)
    decision = propose(claims, verdicts, tai=False, privileged=True)
    assert decision.level == "APPROVE"
    assert decision.action == "disable_account"
    assert decision.level != "AUTO"


def test_excluded_rejection_is_written_to_the_audit_log(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("gate.AUDIT_PATH", tmp_path / "audit.jsonl")
    claims = [
        _claim("drop", ClaimType.LSASS_ACCESS, "The 4688 row dumped LSASS.", host="workstation5"),
        _claim("keep", ClaimType.LSASS_ACCESS, "Event 10 opened lsass.", host="workstation5"),
    ]
    decision = recommend_gate(
        claims,
        [_verdict("drop", "REJECTED"), _verdict("keep", "VERIFIED")],
    )
    assert decision.level == "APPROVE"
    lines = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert lines[0]["actor"] == "oracle"
    assert lines[0]["action"] == "exclude_claim"
    assert lines[0]["evidence_claim_ids"] == ["drop"]
    assert lines[0]["gate_decision"] == "APPROVE"
    assert lines[0]["executed"] is False
    assert "hash" not in lines[0]


def test_i01_titan_path_is_deny_or_approve_with_tai() -> None:
    frame = load_injections()
    events = frame[frame["injection_id"] == "I01"]
    assert len(events) == 1
    findings = scan_events(events)
    assert findings
    alerts = detect(events)
    claims = claims_from_alerts(alerts)
    verdicts = verify_all(claims, events.to_dict(orient="records"))
    decision = propose(claims, verdicts, tai=True, privileged=True)
    assert decision.level in {"DENY", "APPROVE"}
    assert decision.level != "AUTO"
    if decision.level == "APPROVE" and decision.action == "disable_account":
        assert "T-AI" in decision.reason


def test_approve_writes_the_mock_and_deny_only_writes_audit(tmp_path) -> None:
    actions = tmp_path / "actions_executed.jsonl"
    audit = tmp_path / "audit.jsonl"
    approved = propose(
        [_claim("c1", ClaimType.PROCESS_EXECUTED, "rundll32 ran MiniDump.")],
        [_verdict("c1", "VERIFIED")],
        tai=True,
    )
    execute(
        approved,
        actor="analyst",
        evidence_ids=["c1"],
        injection_ids=["I01"],
        actions_path=actions,
        audit_path=audit,
    )
    denied = propose(
        [_claim("c1", ClaimType.LSASS_ACCESS, "rundll32 dumped lsass.")],
        [_verdict("c1", "REJECTED")],
    )
    execute(
        denied,
        actor="analyst",
        evidence_ids=["c1"],
        injection_ids=["I01"],
        actions_path=actions,
        audit_path=audit,
    )
    record_audit(
        actor="analyst",
        action="disable_account",
        evidence_ids=["c1"],
        gate_decision="DENY",
        injection_ids=["I01"],
        audit_path=audit,
        executed=False,
    )
    action_lines = [json.loads(line) for line in actions.read_text(encoding="utf-8").splitlines()]
    audit_lines = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert len(action_lines) == 1
    assert action_lines[0]["action"] == "disable_account"
    assert action_lines[0]["injection_ids"] == ["I01"]
    assert action_lines[0]["gate_decision"] == "APPROVE"
    assert "hash" not in action_lines[0]
    assert [line["gate_decision"] for line in audit_lines] == ["APPROVE", "DENY", "DENY"]
    assert audit_lines[0]["executed"] is True
    assert audit_lines[1]["executed"] is False
    assert audit_lines[2]["evidence_claim_ids"] == ["c1"]
    assert "hash" not in audit_lines[2]
    assert "prev_hash" not in audit_lines[2]
