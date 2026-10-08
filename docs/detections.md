# Detection logic

| Rule | What it looks for | Default trigger | ATT&CK |
|---|---|---|---|
| `portscan` | SYN-only packets to many distinct (host, port) pairs from one source | >= 30 targets / 10 s; HIGH at >= 90 | T1046 |
| `bruteforce` | Failed logins per (source, service); many usernames = spraying; success after failures = CRITICAL; SYN rate to auth ports in PCAPs | >= 8 failures / 120 s; >= 25 SYN / 120 s | T1110, T1110.003, T1078 |
| `dns` | DGA-like labels (length, Shannon entropy, digit/vowel ratio) across >= 3 domains; tunnelling (unique subdomains, avg name length, TXT/NULL volume) | 40 unique names / 60 s | T1568.002, T1071.004, T1048 |
| `arp` | IP->MAC binding change (CRITICAL for configured gateways); one MAC answering for many IPs | any change; >= 6 IPs per MAC | T1557.002 |
| `rogue_dhcp` | Offers/ACKs from a server not in `allowed_servers` (or >1 server when no list) | any | T1557.003 |
| `new_device` | Source MAC not in the inventory file | any unknown unicast MAC | T1200 |

## Known limitations
- IPv4 only; no TLS/JA3 analysis; PCAP is read offline (no live sniffing yet).
- The ARP rule can false-positive when a host legitimately changes NIC or DHCP lease: use `ignore_macs`.
- Entropy heuristics produce false positives on CDN hash names: use `dns.allowlist`.
- Registered-domain split uses a small built-in multi-label suffix list, not the full Public Suffix List.
- Thresholds are starting points; tune them per network with `rules/default.yaml`.

## Adding a detector
Create `netwatch/detectors/my_rule.py` with a `Detector` subclass (`name`, `feed(event)`), register it in
`detectors/__init__.py`, add its defaults to `config.py`, and write a test in `tests/test_detectors.py`.
