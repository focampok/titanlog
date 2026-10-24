"""Gate levels and the local audit log. No live LLM calls."""

from __future__ import annotations

import json

from agents import claims_from_alerts
from claims import Claim, ClaimType, ClaimVerdict
from detectors import detect
from gate import execute, propose, record_audit
from inject import load_injections
from inject_scan import scan_events
from oracle import verify_all


def _claim(claim_id: str, claim_type: ClaimType, statement: str) -> Claim:
    return Claim(
        claim_id=claim_id,
        claim_type=claim_type,
        statement=statement,
        row_id="row-1",
        confidence=1,
    )


def _verdict(claim_id: str, status: str) -> ClaimVerdict:
    return ClaimVerdict(claim_id=claim_id, status=status, reason="fixture")


def test_rejected_evidence_is_deny_and_never_auto() -> None:
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
    rejected = any(
        verdict.status == "REJECTED" and claim.claim_type != ClaimType.AUTHORIZATION
        for claim in claims
        for verdict in verdicts
        if verdict.claim_id == claim.claim_id
    )
    if rejected:
        assert decision.level == "DENY"
    else:
        assert decision.level == "APPROVE"
    assert decision.level != "AUTO"


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
