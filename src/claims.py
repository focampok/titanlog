"""P0 claim contract. The Oracle accepts only these six types."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class ClaimType(str, Enum):
    """Claim types the P0 Oracle verifies.

    P1 types are unused: file_created, scheduled_task, lateral_logon,
    severity, action_recommended. T1053.005 (scheduled task) is P1.
    """

    PROCESS_EXECUTED = "process_executed"
    LSASS_ACCESS = "lsass_access"
    SERVICE_INSTALLED = "service_installed"
    ENCODED_POWERSHELL = "encoded_powershell"
    AUTHORIZATION = "authorization"
    ATTACK_TECHNIQUE = "attack_technique"


class Claim(BaseModel):
    """One statement the investigator asks the Oracle to check."""

    claim_id: str
    claim_type: ClaimType
    statement: str = Field(..., description="Short English phrase")
    host: str | None = None
    user: str | None = None
    technique_id: str | None = None
    row_id: str | None = Field(
        default=None,
        description="Required for every P0 type except authorization.",
    )
    field: str | None = Field(default=None, description="Event field the claim cites")
    expected_value_substring: str | None = None
    confidence: float = Field(ge=0, le=1)


class ClaimVerdict(BaseModel):
    """Deterministic result for one claim. Confidence is not evidence."""

    claim_id: str
    status: Literal["VERIFIED", "REJECTED", "UNVERIFIABLE"]
    reason: str
