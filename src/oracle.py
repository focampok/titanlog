"""Deterministic Oracle for the six P0 claim types.

A cited host or user must match the row. Hosts use the ingest host key.
Split-context injections (I10/I11) are a known limitation: each claim is
checked against its own cited row, and text is not stitched across events.

authorization is a deliberate stub. The demo allowlist is empty, so those
claims are REJECTED. Only an allowlist ticket counts. Production would query
ServiceNow or Jira.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Literal

from claims import Claim, ClaimType, ClaimVerdict
from detectors import dangerous_access
from titanlog.adapters.generic_jsonl import coerce_event_code, host_key_for

# Same token rule as detectors.encoded_powershell: "-enc" is not "-Encoding".
_ENC = re.compile(r"(?:^|[^a-z0-9])-enc(?:odedcommand)?(?:[^a-z0-9]|$)")
_B64 = re.compile(r"frombase64string")

Status = Literal["VERIFIED", "REJECTED", "UNVERIFIABLE"]

# Fixed P0 map. P1 T1053.005 (scheduled task) is intentionally absent.
P0_TECHNIQUES: dict[str, frozenset[ClaimType]] = {
    "T1003.001": frozenset({ClaimType.LSASS_ACCESS, ClaimType.PROCESS_EXECUTED}),
    "T1059.001": frozenset({ClaimType.ENCODED_POWERSHELL}),
    "T1569.002": frozenset({ClaimType.SERVICE_INSTALLED}),
    "T1021.002": frozenset({ClaimType.SERVICE_INSTALLED}),
}

# Empty in the demo. A ticket row is {"ticket_id": "...", "host": "..."} .
DEMO_ALLOWLIST: tuple[Any, ...] = ()

_FIELD_NAMES = {
    "commandline": "command_line",
    "process.command_line": "command_line",
    "process_command_line": "command_line",
    "image": "image",
    "process.executable": "image",
    "process_executable": "image",
    "newprocessname": "image",
    "targetimage": "target",
    "target.process.executable": "target",
    "target_process_executable": "target",
    "sourceimage": "source",
    "grantedaccess": "granted",
    "granted_access": "granted",
    "servicename": "service_name",
    "service.name": "service_name",
    "service_name": "service_name",
    "servicefilename": "service_path",
    "imagepath": "service_path",
    "service.path": "service_path",
    "service_path": "service_path",
}


def verify_claim(
    claim: Claim,
    events: Iterable[Any],
    *,
    claims: Sequence[Claim] | None = None,
    allowlist: Iterable[Any] | None = None,
) -> ClaimVerdict:
    """Verify one claim.

    authorization is a deliberate stub. The demo allowlist is empty, so those
    claims are REJECTED. A command line, file path, or message is not a ticket.
    Production would query ServiceNow or Jira: a matching allowlist ticket
    verifies the claim.
    """
    rows = _rows(events)
    tickets = tuple(DEMO_ALLOWLIST if allowlist is None else allowlist)
    if claim.claim_type is ClaimType.AUTHORIZATION:
        return _authorization(claim, tickets)
    if claim.claim_type is ClaimType.ATTACK_TECHNIQUE:
        return _attack_technique(claim, rows, claims or (), tickets)
    row, blocked = _bound(claim, rows)
    if blocked is not None:
        return blocked
    assert row is not None
    if claim.claim_type is ClaimType.PROCESS_EXECUTED:
        return _process_executed(claim, row)
    if claim.claim_type is ClaimType.LSASS_ACCESS:
        return _lsass_access(claim, row)
    if claim.claim_type is ClaimType.SERVICE_INSTALLED:
        return _service_installed(claim, row)
    if claim.claim_type is ClaimType.ENCODED_POWERSHELL:
        return _encoded_powershell(claim, row)
    return _verdict(claim, "UNVERIFIABLE", "No verifier for this claim type.")


def verify_all(
    claims: Sequence[Claim],
    events: Iterable[Any],
    *,
    allowlist: Iterable[Any] | None = None,
) -> list[ClaimVerdict]:
    """Verify each claim. Technique claims see the rest of this batch."""
    rows = _rows(events)
    tickets = tuple(DEMO_ALLOWLIST if allowlist is None else allowlist)
    return [verify_claim(claim, rows, claims=claims, allowlist=tickets) for claim in claims]


def _authorization(claim: Claim, allowlist: Sequence[Any]) -> ClaimVerdict:
    """Deliberate stub.

    These datasets have no change tickets. The demo allowlist is empty, so
    the claim is REJECTED. Only a ticket row on the allowlist can verify it,
    and only when the claim statement cites that ticket id. Production would
    query ServiceNow or Jira. A command line, file path, or message is not a
    ticket.
    """
    for row in allowlist:
        ticket = _ticket(row)
        if ticket is None:
            continue
        ticket_id, host = ticket
        if host and (not claim.host or host_key_for(host) != host_key_for(claim.host)):
            continue
        if _cites(claim.statement, ticket_id):
            return _verdict(
                claim,
                "VERIFIED",
                f"Allowlist ticket {ticket_id} matches this claim. "
                "Production would query ServiceNow or Jira.",
            )
    return _verdict(
        claim,
        "REJECTED",
        "No matching allowlist ticket. A command line is not a ticket. "
        "Production would query ServiceNow or Jira.",
    )


def _process_executed(claim: Claim, row: Any) -> ClaimVerdict:
    code = _code(row)
    if code not in {1, 4688}:
        return _verdict(claim, "REJECTED", "Event is not a process execution (1 or 4688).")
    texts = _cited(claim, row, ("command_line", "image"))
    if texts is None:
        return _verdict(claim, "REJECTED", "Cited field is not the image or command line.")
    needle = _needle(claim)
    if needle is None:
        return _verdict(claim, "UNVERIFIABLE", "Process claim needs a substring to check.")
    if not _contains(texts, needle):
        return _verdict(claim, "REJECTED", "Cited text is not in the image or command line.")
    return _verdict(
        claim,
        "VERIFIED",
        f"Event {code} image or command line contains the cited text.",
    )


def _lsass_access(claim: Claim, row: Any) -> ClaimVerdict:
    if _code(row) != 10:
        return _verdict(claim, "REJECTED", "Event is not a process-access event (10).")
    fields = _values(row)
    if "lsass" not in fields["target"].casefold():
        return _verdict(claim, "REJECTED", "Target image is not lsass.")
    source = fields["source"].casefold()
    dangerous = dangerous_access(fields["granted"])
    source_ok = "rundll32" in source or "comsvcs" in source
    if not dangerous and not source_ok:
        return _verdict(
            claim,
            "REJECTED",
            "Granted access is not dangerous, and the source is not rundll32 or comsvcs.",
        )
    texts = _cited(claim, row, ("target", "source", "granted"))
    if texts is None:
        return _verdict(claim, "REJECTED", "Cited field is not evidence for lsass access.")
    needle = _needle(claim)
    if needle is not None and not _contains(texts, needle):
        return _verdict(claim, "REJECTED", "Cited text is not in the lsass access fields.")
    if dangerous:
        reason = "Event 10 targets lsass with dangerous granted access."
    else:
        reason = "Event 10 targets lsass from rundll32 or comsvcs."
    return _verdict(claim, "VERIFIED", reason)


def _service_installed(claim: Claim, row: Any) -> ClaimVerdict:
    code = _code(row)
    if code not in {4697, 7045}:
        return _verdict(claim, "REJECTED", "Event is not a service installation (4697 or 7045).")
    texts = _cited(claim, row, ("service_name", "service_path"))
    if texts is None:
        return _verdict(claim, "REJECTED", "Cited field is not the service name or path.")
    needle = _needle(claim)
    if needle is None:
        return _verdict(claim, "UNVERIFIABLE", "Service claim needs a substring to check.")
    if not _contains(texts, needle):
        return _verdict(claim, "REJECTED", "Cited text is not in the service name or path.")
    return _verdict(
        claim,
        "VERIFIED",
        f"Event {code} service name or path contains the cited text.",
    )


def _encoded_powershell(claim: Claim, row: Any) -> ClaimVerdict:
    texts = _cited(claim, row, ("command_line", "service_path"))
    if texts is None:
        return _verdict(claim, "REJECTED", "Cited field is not the command line or service path.")
    blob = "\n".join(texts).casefold()
    if _ENC.search(blob) is None and _B64.search(blob) is None:
        return _verdict(
            claim,
            "REJECTED",
            "Command line and service path have no encoded PowerShell marker.",
        )
    needle = _needle(claim)
    if needle is not None and not _contains(texts, needle):
        return _verdict(claim, "REJECTED", "Cited text is not in the command line or service path.")
    return _verdict(
        claim,
        "VERIFIED",
        "Command line or service path contains an encoded PowerShell marker.",
    )


def _attack_technique(
    claim: Claim,
    rows: list[Any],
    others: Sequence[Claim],
    allowlist: Sequence[Any],
) -> ClaimVerdict:
    row, blocked = _bound(claim, rows)
    if blocked is not None:
        return blocked
    assert row is not None
    technique_id = (claim.technique_id or "").strip().upper()
    if not technique_id:
        return _verdict(claim, "UNVERIFIABLE", "Technique claim needs a technique id.")
    needed = P0_TECHNIQUES.get(technique_id)
    if needed is None:
        return _verdict(claim, "REJECTED", f"{technique_id} is outside the P0 technique map.")
    technique_host = _host_key(claim, rows)
    for other in others:
        if other is claim or other.claim_type is ClaimType.ATTACK_TECHNIQUE:
            continue
        verdict = verify_claim(other, rows, allowlist=allowlist)
        if verdict.status != "VERIFIED" or other.claim_type not in needed:
            continue
        evidence_host = _host_key(other, rows)
        if technique_host and evidence_host and technique_host != evidence_host:
            continue
        return _verdict(
            claim,
            "VERIFIED",
            f"{technique_id} is supported by verified {other.claim_type.value} evidence.",
        )
    return _verdict(claim, "REJECTED", f"No verified evidence claim supports {technique_id}.")


def _bound(claim: Claim, rows: list[Any]) -> tuple[Any | None, ClaimVerdict | None]:
    if not (claim.row_id and claim.row_id.strip()):
        return None, _verdict(claim, "REJECTED", "row_id is required.")
    row = _index(rows).get(claim.row_id)
    if row is None:
        return None, _verdict(claim, "REJECTED", "Cited row is not in the evidence.")
    if not _same_host(claim.host, row):
        return None, _verdict(claim, "REJECTED", "Host does not match the cited row.")
    if not _same_user(claim.user, _text(_pick(row, "user_name"))):
        return None, _verdict(claim, "REJECTED", "User does not match the cited row.")
    return row, None


def _cited(claim: Claim, row: Any, allowed: tuple[str, ...]) -> tuple[str, ...] | None:
    values = _values(row)
    if claim.field is None or not claim.field.strip():
        return tuple(values[name] for name in allowed)
    name = _FIELD_NAMES.get(claim.field.strip().casefold())
    if name is None or name not in allowed:
        return None
    return (values[name],)


def _values(row: Any) -> dict[str, str]:
    image = _text(_pick(row, "process_executable")) or _raw(row, "Image") or _raw(row, "NewProcessName")
    return {
        "command_line": _text(_pick(row, "process_command_line")) or _raw(row, "CommandLine"),
        "image": image,
        "target": _text(_pick(row, "target_process_executable")) or _raw(row, "TargetImage"),
        "source": _raw(row, "SourceImage") or _text(_pick(row, "process_executable")),
        "granted": _text(_pick(row, "granted_access")) or _raw(row, "GrantedAccess"),
        "service_name": _text(_pick(row, "service_name")) or _raw(row, "ServiceName"),
        "service_path": (
            _text(_pick(row, "service_path"))
            or _raw(row, "ServiceFileName")
            or _raw(row, "ImagePath")
        ),
    }


def _contains(texts: tuple[str, ...], needle: str) -> bool:
    folded = needle.casefold()
    return any(folded in text.casefold() for text in texts)


def _needle(claim: Claim) -> str | None:
    text = claim.expected_value_substring
    if text is None:
        return None
    stripped = text.strip()
    return stripped or None


def _host_key(claim: Claim, rows: list[Any]) -> str | None:
    if claim.host:
        return host_key_for(claim.host)
    if not claim.row_id:
        return None
    row = _index(rows).get(claim.row_id)
    if row is None:
        return None
    return _text(_pick(row, "host_key")) or host_key_for(_text(_pick(row, "host_name")))


def _same_host(claim_host: str | None, row: Any) -> bool:
    if claim_host is None or not claim_host.strip():
        return True
    wanted = host_key_for(claim_host)
    if wanted is None:
        return False
    found = _text(_pick(row, "host_key")) or host_key_for(_text(_pick(row, "host_name")))
    return wanted == found


def _same_user(claim_user: str | None, event_user: str) -> bool:
    if claim_user is None or not claim_user.strip():
        return True
    if not event_user:
        return False
    return claim_user.strip().casefold() == event_user.casefold()


def _cites(statement: str, ticket_id: str) -> bool:
    pattern = rf"(?<![A-Za-z0-9]){re.escape(ticket_id)}(?![A-Za-z0-9])"
    return re.search(pattern, statement, flags=re.IGNORECASE) is not None


def _ticket(row: Any) -> tuple[str, str | None] | None:
    if isinstance(row, Mapping):
        ticket_id = row.get("ticket_id")
        host = row.get("host")
    else:
        ticket_id = getattr(row, "ticket_id", None)
        host = getattr(row, "host", None)
    text = _text(ticket_id)
    if not text:
        return None
    host_text = _text(host)
    return text, host_text or None


def _index(rows: Sequence[Any]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for row in rows:
        row_id = _text(_pick(row, "row_id"))
        if row_id and row_id not in found:
            found[row_id] = row
    return found


def _rows(events: Iterable[Any]) -> list[Any]:
    if hasattr(events, "to_dict"):
        return list(events.to_dict("records"))
    return list(events)


def _code(row: Any) -> int | None:
    value = _pick(row, "event_code")
    if isinstance(value, bool) or _missing(value):
        return None
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if math.isnan(value) or not value.is_integer():
            return None
        return int(value)
    if isinstance(value, str):
        return coerce_event_code(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _raw(row: Any, key: str) -> str:
    raw = _pick(row, "raw")
    if isinstance(raw, Mapping):
        return _text(raw.get(key))
    return ""


def _pick(row: Any, key: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(key)
    return getattr(row, key, None)


def _missing(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    return type(value).__name__ == "NAType"


def _text(value: Any) -> str:
    if _missing(value):
        return ""
    text = str(value).strip()
    if text in {"-", "None", "<NA>"}:
        return ""
    return text


def _verdict(claim: Claim, status: Status, reason: str) -> ClaimVerdict:
    return ClaimVerdict(claim_id=claim.claim_id, status=status, reason=reason)
