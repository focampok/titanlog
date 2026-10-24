"""Human gate for disable_account. Execution is a local JSONL mock.

A rejected evidence claim is dropped and logged unless it is the only evidence
for its account or host. AUTO is only for a low-impact account when every
remaining evidence claim is verified and the scan found no T-AI hit.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

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
    close: bool = False,
    severity: str | None = None,
) -> GateRecommendation:
    """Propose disable_account from Oracle verdicts.

    DENY when a rejected claim is the only evidence for its account or host,
    when the action would rest on an authorization claim that is not VERIFIED,
    or when a close or benign decision relies on injected text. Other rejected
    claims are excluded. APPROVE when impact is high, a T-AI finding is present,
    or any evidence was rejected or left insufficient. AUTO is the remaining
    low-impact case.
    """
    by_id = {verdict.claim_id: verdict for verdict in verdicts}
    evidence = [claim for claim in claims if claim.claim_type in _EVIDENCE and claim.claim_id in by_id]
    authorization = [
        claim for claim in claims if claim.claim_type == ClaimType.AUTHORIZATION and claim.claim_id in by_id
    ]
    if _close_relies_on_injection(close=close, severity=severity, tai=tai):
        return _decision(
            "DENY",
            "disable_account",
            "The close or benign decision relies on injected text. Containment stays blocked.",
        )
    verified_claims = [claim for claim in evidence if by_id[claim.claim_id].status == "VERIFIED"]
    rejected = [claim for claim in evidence if by_id[claim.claim_id].status == "REJECTED"]
    load_bearing = [claim for claim in rejected if not _supported(claim, verified_claims)]
    if load_bearing:
        return _decision(
            "DENY",
            "disable_account",
            "A rejected claim is the only evidence for its account or host. Containment stays blocked.",
        )
    excluded = [claim.claim_id for claim in rejected]
    kept = [claim for claim in evidence if claim.claim_id not in set(excluded)]
    kept_status = [by_id[claim.claim_id].status for claim in kept]
    verified = any(status == "VERIFIED" for status in kept_status)
    insufficient = any(status == "UNVERIFIABLE" for status in kept_status)
    if authorization and not verified and any(by_id[claim.claim_id].status != "VERIFIED" for claim in authorization):
        return _decision(
            "DENY",
            "disable_account",
            "The action would rely on an authorization claim that is not verified.",
            excluded,
        )
    if not verified:
        return _decision(
            "APPROVE",
            "none",
            _with_exclusions("No verified evidence. No containment action is recommended.", excluded),
            excluded,
        )
    if privileged or tai or excluded or insufficient:
        reason = "Verified evidence supports disabling the account. A human approves this action."
        if tai:
            reason = (
                "Verified evidence supports disabling the account. "
                "A T-AI finding is present, so a human approves this action."
            )
        return _decision("APPROVE", "disable_account", _with_exclusions(reason, excluded), excluded)
    return _decision(
        "AUTO",
        "disable_account",
        "All evidence claims are verified, impact is low, and no T-AI finding is present.",
    )


def _decision(
    level: Literal["AUTO", "APPROVE", "DENY"],
    action: str,
    reason: str,
    excluded: list[str] | None = None,
) -> GateRecommendation:
    return GateRecommendation(
        level=level,
        action=action,
        reason=reason,
        excluded_claim_ids=list(excluded or []),
    )


def _with_exclusions(reason: str, excluded: list[str]) -> str:
    if not excluded:
        return reason
    note = f"{len(excluded)} claim(s) rejected by Oracle and excluded"
    return f"{reason} {note}."


def _close_relies_on_injection(*, close: bool, severity: str | None, tai: bool) -> bool:
    benign = close or (severity or "").strip().upper() in {"BENIGN", "LOW"}
    return bool(tai and benign)


def _supported(rejected: Claim, verified: list[Claim]) -> bool:
    """True when some other verified claim still covers this account or host."""
    host = _scope(rejected.host)
    user = _scope(rejected.user)
    for other in verified:
        if other.claim_id == rejected.claim_id:
            continue
        if host and host == _scope(other.host):
            return True
        if user and user == _scope(other.user):
            return True
        if not host and not user:
            return True
    return False


def _scope(value: str | None) -> str:
    return (value or "").strip().casefold()


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
