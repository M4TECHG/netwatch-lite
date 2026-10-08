from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "portscan": {
        "enabled": True,
        "window_seconds": 10,
        "distinct_targets": 30,  # distinct (host, port) pairs probed with SYN-only
    },
    "bruteforce": {
        "enabled": True,
        "window_seconds": 120,
        "failed_logins": 8,
        "spray_users": 5,  # distinct usernames from one source => password spraying
        "auth_ports": [21, 22, 23, 445, 3389, 5900],
        "connection_attempts": 25,  # SYNs to one auth port inside the window (pcap heuristic)
    },
    "dns": {
        "enabled": True,
        "window_seconds": 60,
        "min_label_length": 16,
        "entropy_threshold": 3.5,
        "unique_subdomains": 40,
        "avg_query_length": 50,
        "txt_null_queries": 20,
        "allowlist": ["cloudfront.net", "amazonaws.com", "akamaiedge.net", "googleusercontent.com"],
    },
    "arp": {
        "enabled": True,
        "gateways": [],
        "ips_per_mac": 6,
        "ignore_macs": [],
    },
    "rogue_dhcp": {
        "enabled": True,
        "allowed_servers": [],
    },
    "new_device": {
        "enabled": True,
        "known_macs": [],
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        with open(path, encoding="utf-8") as fh:
            cfg = deep_merge(cfg, yaml.safe_load(fh) or {})
    return cfg


def load_inventory(path: str | Path) -> list[str]:
    """Read known MAC addresses from a CSV/TXT file (first column = MAC)."""
    macs: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        first = line.split(",")[0].strip().lower().replace("-", ":")
        if len(first.split(":")) == 6:
            macs.append(first)
    return macs
