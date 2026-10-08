from .arp import ArpSpoofDetector
from .bruteforce import BruteForceDetector
from .dns import DnsDetector
from .new_device import NewDeviceDetector
from .portscan import PortScanDetector
from .rogue_dhcp import RogueDhcpDetector

REGISTRY = {
    cls.name: cls
    for cls in (
        PortScanDetector,
        BruteForceDetector,
        DnsDetector,
        ArpSpoofDetector,
        RogueDhcpDetector,
        NewDeviceDetector,
    )
}
