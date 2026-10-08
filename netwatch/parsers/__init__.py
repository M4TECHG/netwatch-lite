from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..models import Event
from .authlog import parse_auth_file
from .pcap import parse_pcap

PCAP_MAGICS = {
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
    bytes.fromhex("0a0d0d0a"),  # pcapng
}


def detect_kind(path: str | Path) -> str:
    p = Path(path)
    with open(p, "rb") as fh:
        magic = fh.read(4)
    if magic in PCAP_MAGICS:
        return "pcap"
    return "auth"


def parse_file(path: str | Path, year: int | None = None) -> Iterator[Event]:
    if detect_kind(path) == "pcap":
        return parse_pcap(path)
    return parse_auth_file(path, year=year)
