"""MITRE ATT&CK technique mapping used by the detectors."""

TECHNIQUES = {
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1078": ("Valid Accounts", "Defense Evasion / Persistence"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1568.002": ("Dynamic Resolution: Domain Generation Algorithms", "Command and Control"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1557.002": ("Adversary-in-the-Middle: ARP Cache Poisoning", "Credential Access"),
    "T1557.003": ("Adversary-in-the-Middle: DHCP Spoofing", "Credential Access"),
    "T1200": ("Hardware Additions", "Initial Access"),
}


def technique(tid: str) -> dict[str, str]:
    name, tactic = TECHNIQUES[tid]
    return {
        "id": tid,
        "name": name,
        "tactic": tactic,
        "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/",
    }
