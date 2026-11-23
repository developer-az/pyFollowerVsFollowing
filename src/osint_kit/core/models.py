"""Report models.

``Finding`` and ``Report`` are the only data shapes the renderers know about.
Plugins stay free to compute in dataclasses; they convert at the boundary so a
report is always JSON-serialisable.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    """Timezone-aware UTC now (kept as a function for easy test patching)."""
    return datetime.now(UTC)


class Severity(StrEnum):
    """How much attention a finding deserves."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        """Ordering helper: higher rank means more severe."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


class Finding(BaseModel):
    """One observation, suitable for a table row or a JSON record."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: str = Field(min_length=1, description="Stable machine key, e.g. 'non_follower'.")
    subject: str = Field(min_length=1, description="The thing observed, e.g. a username or IP.")
    summary: str = Field(min_length=1, description="One human sentence.")
    severity: Severity = Severity.INFO
    details: dict[str, Any] = Field(default_factory=dict)
    tags: tuple[str, ...] = ()


class Report(BaseModel):
    """Everything one plugin run produced."""

    model_config = ConfigDict(extra="forbid")

    plugin: str
    target: str = Field(description="What was analysed, for the record.")
    generated_at: datetime = Field(default_factory=utcnow)
    findings: list[Finding] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def add(
        self,
        *,
        category: str,
        subject: str,
        summary: str,
        severity: Severity = Severity.INFO,
        details: dict[str, Any] | None = None,
        tags: Iterable[str] = (),
    ) -> Finding:
        """Append a finding and return it."""
        finding = Finding(
            category=category,
            subject=subject,
            summary=summary,
            severity=severity,
            details=details or {},
            tags=tuple(tags),
        )
        self.findings.append(finding)
        return finding

    def extend(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    def severity_counts(self) -> dict[str, int]:
        counts = {level.value: 0 for level in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
