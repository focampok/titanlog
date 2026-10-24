"""Human gate for disable_account. Execution is a local JSONL mock.

AUTO is only for a low-impact account when every evidence claim is verified
and the scan found no T-AI hit. A rejected evidence claim is never AUTO.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from claims import Claim, ClaimType, ClaimVerdict
from correlate import GateRecommendation

_EVIDENCE = {
    ClaimType.PROCESS_EXECUTED,
    ClaimType.LSASS_ACCESS,
    ClaimType.SERVICE_INSTALLED,
    ClaimType.ENCODED_POWERSHELL,
    ClaimType.ATTACK_TECHNIQUE,
}
_REPO = Path(__file__).resolve().parents[1]
ACTIONS_PATH = _REPO / "results" / "actions_executed.jsonl"
AUDIT_PATH = _REPO / "results" / "audit.jsonl"


def propose(
    claims: list[Claim],
    verdicts: list[ClaimVerdict],
    *,
    tai: bool = False,
    privileged: bool = True,
) -> GateRecommendation:
    """Propose disable_account from Oracle verdicts.

    DENY when an evidence claim is REJECTED, or the action would rest on an
    authorization claim that is not VERIFIED. APPROVE when the account impact
    is high or a T-AI finding is present. AUTO is the remaining low-impact case.
    """
    by_id = {verdict.claim_id: verdict for verdict in verdicts}
    evidence = [claim for claim in claims if claim.claim_type in _EVIDENCE and claim.claim_id in by_id]
    evidence_status = [by_id[claim.claim_id].status for claim in evidence]
    authorization = [
        claim for claim in claims if claim.claim_type == ClaimType.AUTHORIZATION and claim.claim_id in by_id
    ]
    verified = any(status == "VERIFIED" for status in evidence_status)
    if any(status == "REJECTED" for status in evidence_status):
        return GateRecommendation(
            level="DENY",
            action="disable_account",
            reason="An evidence claim was rejected. Containment stays blocked.",
        )
    if authorization and not verified and any(by_id[claim.claim_id].status != "VERIFIED" for claim in authorization):
        return GateRecommendation(
            level="DENY",
            action="disable_account",
            reason="The action would rely on an authorization claim that is not verified.",
        )
    if not verified:
        return GateRecommendation(
            level="APPROVE",
            action="none",
            reason="No verified evidence. No containment action is recommended.",
        )
    if privileged or tai:
        reason = "Verified evidence supports disabling the account. A human approves this action."
        if tai:
            reason = (
                "Verified evidence supports disabling the account. "
                "A T-AI finding is present, so a human approves this action."
            )
        return GateRecommendation(level="APPROVE", action="disable_account", reason=reason)
    return GateRecommendation(
        level="AUTO",
        action="disable_account",
        reason="All evidence claims are verified, impact is low, and no T-AI finding is present.",
    )


def evidence_claim_ids(claims: list[Claim]) -> list[str]:
    """Claim ids the gate can cite. Authorization claims are not evidence."""
    return [claim.claim_id for claim in claims if claim.claim_type in _EVIDENCE]


def execute(
    decision: GateRecommendation,
    *,
    actor: str,
    evidence_ids: list[str],
    injection_ids: list[str] | None = None,
    actions_path: str | Path | None = None,
    audit_path: str | Path | None = None,
) -> dict[str, Any]:
    """Append the mock action and an audit line. DENY and action none do not execute."""
    injections = list(injection_ids or [])
    if decision.level == "DENY" or decision.action != "disable_account":
        return record_audit(
            actor=actor,
            action=decision.action,
            evidence_ids=evidence_ids,
            gate_decision=decision.level,
            injection_ids=injections,
            audit_path=audit_path,
            executed=False,
        )
    record = record_audit(
        actor=actor,
        action="disable_account",
        evidence_ids=evidence_ids,
        gate_decision=decision.level,
        injection_ids=injections,
        audit_path=audit_path,
        executed=True,
    )
    _append(
        Path(actions_path) if actions_path is not None else ACTIONS_PATH,
        {
            "ts": record["ts"],
            "actor": actor,
            "action": "disable_account",
            "evidence_claim_ids": list(evidence_ids),
            "gate_decision": decision.level,
            "injection_ids": injections,
        },
    )
    return record


def record_audit(
    *,
    actor: str,
    action: str,
    evidence_ids: list[str],
    gate_decision: str,
    injection_ids: list[str] | None = None,
    audit_path: str | Path | None = None,
    executed: bool = False,
) -> dict[str, Any]:
    """Append one audit object. There is no hash chain."""
    record = {
        "ts": datetime.now(UTC).isoformat(),
        "actor": actor,
        "action": action,
        "evidence_claim_ids": list(evidence_ids),
        "gate_decision": gate_decision,
        "injection_ids": list(injection_ids or []),
        "executed": executed,
    }
    _append(Path(audit_path) if audit_path is not None else AUDIT_PATH, record)
    return record


def _append(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
