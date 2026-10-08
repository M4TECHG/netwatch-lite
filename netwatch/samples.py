"""Synthetic traffic generator: builds a PCAP + auth.log + inventory containing one of each attack."""

from __future__ import annotations

import random
from datetime import datetime, timezone
from pathlib import Path

GW_IP, GW_MAC = "192.168.10.1", "aa:bb:cc:00:00:01"
DHCP_IP, DHCP_MAC = "192.168.10.2", "aa:bb:cc:00:00:02"
SRV_IP, SRV_MAC = "192.168.10.5", "aa:bb:cc:00:00:05"
PC_IP, PC_MAC = "192.168.10.20", "aa:bb:cc:00:00:20"
TUN_IP, TUN_MAC = "192.168.10.31", "aa:bb:cc:00:00:31"
ATT_IP, ATT_MAC = "192.168.10.66", "de:ad:be:ef:00:66"
UNKNOWN_MAC = "02:11:22:33:44:55"

T0 = datetime(2026, 10, 5, 10, 0, 0, tzinfo=timezone.utc).timestamp()


def generate(out: Path) -> tuple[Path, Path, Path]:
    from .utils import scapy_quiet, silence_scapy

    with scapy_quiet():
        from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap
        from scapy.utils import mac2str
    silence_scapy()

    rnd = random.Random(1337)
    pkts = []

    def add(t, p):
        p.time = T0 + t
        pkts.append(p)

    def dns(t, src_ip, src_mac, name, qtype="A"):
        add(
            t,
            Ether(src=src_mac, dst=GW_MAC)
            / IP(src=src_ip, dst=GW_IP)
            / UDP(sport=rnd.randint(40000, 60000), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype)),
        )

    def syn(t, src_ip, src_mac, dst_ip, dport):
        add(
            t,
            Ether(src=src_mac, dst=SRV_MAC)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=rnd.randint(40000, 60000), dport=dport, flags="S"),
        )

    # --- baseline traffic ---
    baseline = ["www.google.com", "github.com", "pypi.org", "mail.example.ir", "update.microsoft.com"] * 4
    for i, name in enumerate(baseline):
        dns(i * 3.0, PC_IP, PC_MAC, name)
        syn(i * 3.0 + 0.5, PC_IP, PC_MAC, SRV_IP, 443)
    add(0.5, Ether(src=GW_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=GW_IP, hwsrc=GW_MAC, pdst=PC_IP))
    add(1.0, Ether(src=SRV_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=SRV_IP, hwsrc=SRV_MAC, pdst=PC_IP))

    # --- DHCP: legit offer, then rogue offer ---
    def offer(t, ip, mac):
        add(
            t,
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src=ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr="192.168.10.100", chaddr=mac2str(PC_MAC))
            / DHCP(options=[("message-type", "offer"), ("server_id", ip), "end"]),
        )

    offer(5, DHCP_IP, DHCP_MAC)
    offer(35, ATT_IP, ATT_MAC)

    # --- port scan: 120 ports in ~6 s ---
    for i, port in enumerate(range(1, 121)):
        syn(60 + i * 0.05, ATT_IP, ATT_MAC, SRV_IP, port)

    # --- SSH brute-force connection-rate (pcap view) ---
    for i in range(40):
        syn(90 + i * 1.0, ATT_IP, ATT_MAC, SRV_IP, 22)

    # --- ARP spoofing of the gateway ---
    add(140, Ether(src=ATT_MAC, dst=PC_MAC) / ARP(op=2, psrc=GW_IP, hwsrc=ATT_MAC, pdst=PC_IP))

    # --- DNS tunnelling (TXT, long base32 labels) + DGA lookups ---
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for i in range(80):
        label = "".join(rnd.choice(alphabet) for _ in range(48))
        dns(160 + i * 0.4, TUN_IP, TUN_MAC, f"{label}.t.evil-tunnel.com", "TXT")
    for i in range(6):
        sld = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(18))
        dns(200 + i * 2, TUN_IP, TUN_MAC, f"{sld}.{rnd.choice(['com', 'net', 'info', 'biz'])}")

    # --- unknown device on the LAN ---
    add(
        230,
        Ether(src=UNKNOWN_MAC, dst=GW_MAC)
        / IP(src="192.168.10.77", dst=GW_IP)
        / TCP(sport=51000, dport=80, flags="S"),
    )

    pkts.sort(key=lambda p: p.time)
    out.mkdir(parents=True, exist_ok=True)
    pcap = out / "demo.pcap"
    wrpcap(str(pcap), pkts)

    # --- auth.log: SSH brute force followed by a successful login ---
    lines = []
    t = datetime(2026, 10, 5, 10, 1, 40, tzinfo=timezone.utc)
    users = ["root", "admin", "ubuntu", "test", "oracle", "pi", "deploy", "user", "ftp", "guest"]
    for i in range(24):
        ts = datetime.fromtimestamp(t.timestamp() + i * 2, tz=timezone.utc).strftime("%b %e %H:%M:%S")
        u = users[i % len(users)]
        lines.append(
            f"{ts} srv01 sshd[2211]: Failed password for invalid user {u} from {ATT_IP} port {40000 + i} ssh2"
        )
    ts = datetime.fromtimestamp(t.timestamp() + 60, tz=timezone.utc).strftime("%b %e %H:%M:%S")
    lines.append(f"{ts} srv01 sshd[2299]: Accepted password for deploy from {ATT_IP} port 41022 ssh2")
    authlog = out / "demo_auth.log"
    authlog.write_text("\n".join(lines) + "\n", encoding="utf-8")

    inv = out / "inventory.csv"
    inv.write_text(
        "# mac,name\n"
        + "\n".join(
            f"{m},{n}"
            for m, n in [
                (GW_MAC, "gateway"),
                (DHCP_MAC, "dhcp"),
                (SRV_MAC, "server"),
                (PC_MAC, "pc-sales"),
                (TUN_MAC, "pc-warehouse"),
                (ATT_MAC, "lab-kali"),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return pcap, authlog, inv
