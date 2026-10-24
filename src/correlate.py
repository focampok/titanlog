"""Group P0 alerts into one incident and measure compression."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from claims import Claim, ClaimVerdict
from detectors import Alert


class Compression(BaseModel):
    """Measured N events → M alerts → incidents. Not an analyst-time estimate."""

    events: int
    alerts: int
    incidents: int

    def label(self) -> str:
        return f"{self.events} → {self.alerts} → {self.incidents}"


class GateRecommendation(BaseModel):
    """Recommended gate for disable_account. P10 owns execution and the audit log."""

    level: Literal["AUTO", "APPROVE", "DENY"]
    action: str
    reason: str
    excluded_claim_ids: list[str] = Field(default_factory=list)


class Incident(BaseModel):
    """One incident holding every P0 alert in the loaded set."""

    alerts: list[Alert] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    window_start: str | None = None
    window_end: str | None = None
    compression: Compression
    claims: list[Claim] = Field(default_factory=list)
    verdicts: list[ClaimVerdict] = Field(default_factory=list)
    severity: str | None = None
    close: bool | None = None
    rationale: str | None = None
    gate: GateRecommendation | None = None
    model_id: str | None = None
    base_url_host: str | None = None
    investigation_mode: str | None = None
    llm_fallback: bool = False


def _as_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _window(stamps: list[str]) -> tuple[str | None, str | None]:
    parsed = [item for item in (_as_utc(stamp) for stamp in stamps) if item is not None]
    if not parsed:
        return None, None
    return min(parsed).isoformat(), max(parsed).isoformat()


def correlate(records: Any, alerts: list[Alert]) -> Incident:
    """Return a single incident when any alert fired. Hosts, users, and the time window are recorded on it."""
    n_events = len(records) if hasattr(records, "__len__") else sum(1 for _ in records)
    hosts = sorted({alert.host for alert in alerts if alert.host}, key=str.casefold)
    users = sorted({alert.user for alert in alerts if alert.user}, key=str.casefold)
    start, end = _window([alert.ts for alert in alerts if alert.ts])
    incidents = 1 if alerts else 0
    return Incident(
        alerts=alerts,
        hosts=hosts,
        users=users,
        window_start=start,
        window_end=end,
        compression=Compression(events=n_events, alerts=len(alerts), incidents=incidents),
    )
