from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


@dataclass(slots=True)
class Event:
    """Normalised event produced by every parser (pcap, auth log, ...)."""

    ts: float
    kind: str  # tcp | dns | arp | dhcp | auth | ip
    src_ip: str | None = None
    dst_ip: str | None = None
    src_mac: str | None = None
    sport: int | None = None
    dport: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Alert:
    rule: str
    severity: str
    title: str
    description: str
    src: str
    first_seen: float
    last_seen: float
    count: int = 1
    mitre: list[dict[str, str]] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule": self.rule,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "src": self.src,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "count": self.count,
            "mitre": self.mitre,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
