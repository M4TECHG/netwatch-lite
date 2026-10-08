from __future__ import annotations

from collections.abc import Iterator

from ..models import Event

DHCP_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 10: "NULL", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}


def parse_pcap(path) -> Iterator[Event]:
    """Stream a .pcap / .pcapng file as normalised events (IPv4 only)."""
    from ..utils import scapy_quiet, silence_scapy

    with scapy_quiet():
        from scapy.all import ARP, BOOTP, DHCP, DNS, IP, TCP, UDP, Ether, PcapReader
    silence_scapy()

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            ts = float(pkt.time)
            mac = pkt[Ether].src.lower() if pkt.haslayer(Ether) else None

            if pkt.haslayer(ARP):
                a = pkt[ARP]
                yield Event(
                    ts,
                    "arp",
                    src_ip=a.psrc,
                    dst_ip=a.pdst,
                    src_mac=a.hwsrc.lower(),
                    extra={"op": "reply" if a.op == 2 else "request"},
                )
                continue

            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]

            if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
                opts = {o[0]: o[1] for o in pkt[DHCP].options if isinstance(o, tuple)}
                msg = DHCP_TYPES.get(opts.get("message-type"), "other")
                server = opts.get("server_id") or ip.src
                yield Event(
                    ts,
                    "dhcp",
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_mac=mac,
                    extra={"msg": msg, "server_ip": server},
                )
                continue

            if pkt.haslayer(UDP) and pkt.haslayer(DNS):
                d = pkt[DNS]
                if d.qr == 0 and d.qd is not None:
                    single = not (
                        isinstance(d.qd, (list, tuple))
                        or (hasattr(d.qd, "__getitem__") and not hasattr(d.qd, "qname"))
                    )
                    q = d.qd if single else d.qd[0]
                    name = q.qname.decode(errors="replace") if isinstance(q.qname, bytes) else str(q.qname)
                    yield Event(
                        ts,
                        "dns",
                        src_ip=ip.src,
                        dst_ip=ip.dst,
                        src_mac=mac,
                        sport=pkt[UDP].sport,
                        dport=pkt[UDP].dport,
                        extra={"qname": name.rstrip(".").lower(), "qtype": QTYPES.get(q.qtype, str(q.qtype))},
                    )
                    continue

            if pkt.haslayer(TCP):
                t = pkt[TCP]
                yield Event(
                    ts,
                    "tcp",
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_mac=mac,
                    sport=t.sport,
                    dport=t.dport,
                    extra={"flags": str(t.flags)},
                )
                continue

            yield Event(ts, "ip", src_ip=ip.src, dst_ip=ip.dst, src_mac=mac)
