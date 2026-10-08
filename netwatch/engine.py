from __future__ import annotations

import heapq
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from .config import load_config, load_inventory
from .detectors import REGISTRY
from .models import Alert, Event, sev_rank
from .parsers import parse_file


@dataclass
class Result:
    alerts: list[Alert]
    files: list[str]
    total_events: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    first_ts: float | None = None
    last_ts: float | None = None


def analyze_events(events: Iterable[Event], cfg: dict) -> tuple[list[Alert], Counter, tuple]:
    detectors = [cls(cfg[name]) for name, cls in REGISTRY.items() if cfg[name].get("enabled", True)]
    kinds: Counter = Counter()
    first = last = None
    for ev in events:
        kinds[ev.kind] += 1
        first = ev.ts if first is None else first
        last = ev.ts
        for d in detectors:
            d.feed(ev)
    alerts = [a for d in detectors for a in d.finalize()]
    alerts.sort(key=lambda a: (-sev_rank(a.severity), a.first_seen))
    for i, a in enumerate(alerts, 1):
        a.id = f"NW-{i:04d}"
    return alerts, kinds, (first, last)


def run(
    paths: list[str], config_path: str | None = None, inventory: str | None = None, year: int | None = None
) -> Result:
    cfg = load_config(config_path)
    if inventory:
        cfg["new_device"]["known_macs"] = list(cfg["new_device"]["known_macs"]) + load_inventory(inventory)
    streams = [parse_file(p, year=year) for p in paths]
    merged = streams[0] if len(streams) == 1 else heapq.merge(*streams, key=lambda e: e.ts)
    alerts, kinds, (first, last) = analyze_events(merged, cfg)
    return Result(alerts, [str(p) for p in paths], sum(kinds.values()), dict(kinds), first, last)
