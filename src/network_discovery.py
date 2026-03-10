"""Network device discovery via ARP table and hostname resolution.

Discovers devices on the local network segment by inspecting the ARP
table and attempting hostname resolution for human-readable names.

Security: This is purely passive — reads the existing ARP cache and
performs standard DNS/NetBIOS lookups. No probing or port scanning.
"""

import logging
import re
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from src.oui_lookup import is_randomized_mac, lookup_vendor, normalize_mac

logger = logging.getLogger(__name__)


@dataclass
class NetworkDevice:
    """A device discovered on the local network via ARP."""

    ip_address: str
    mac_address: str
    interface: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    is_randomized: bool = False
    arp_type: str = "dynamic"  # "dynamic" or "static"
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Post-initialization: look up vendor and check for randomization."""
        if self.vendor is None and self.mac_address:
            self.vendor = lookup_vendor(self.mac_address)
        if self.mac_address:
            self.is_randomized = is_randomized_mac(self.mac_address)


def scan_arp_table() -> list[NetworkDevice]:
    """Read the ARP table to discover devices on the local network.

    Returns:
        List of NetworkDevice objects from the ARP cache.
    """
    logger.info("Reading ARP table for local network devices...")

    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        logger.error("arp command not found.")
        return []
    except subprocess.TimeoutExpired:
        logger.error("ARP table query timed out.")
        return []

    if result.returncode != 0:
        logger.warning("ARP command failed (rc=%d)", result.returncode)
        return []

    devices = _parse_arp_output(result.stdout)

    # Resolve hostnames for discovered devices
    for device in devices:
        device.hostname = _resolve_hostname(device.ip_address)

    logger.info("ARP scan complete: found %d devices.", len(devices))
    return devices


def _parse_arp_output(output: str) -> list[NetworkDevice]:
    """Parse the output of `arp -a`.

    Handles Windows arp output format:
      Interface: 192.168.1.1 --- 0x4
        Internet Address    Physical Address      Type
        192.168.1.2         aa-bb-cc-dd-ee-ff     dynamic

    Args:
        output: Raw stdout from arp command.

    Returns:
        List of NetworkDevice objects.
    """
    devices: list[NetworkDevice] = []
    current_interface = ""
    seen_macs: set[str] = set()

    for line in output.splitlines():
        line = line.strip()

        # Interface line
        iface_match = re.match(r"^Interface:\s*(\S+)", line, re.IGNORECASE)
        if iface_match:
            current_interface = iface_match.group(1)
            continue

        # ARP entry line: IP  MAC  Type
        arp_match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\s+(\w+)",
            line,
        )
        if arp_match:
            ip = arp_match.group(1)
            mac_raw = arp_match.group(2)
            arp_type = arp_match.group(3).lower()

            # Skip broadcast and multicast addresses
            if mac_raw.lower() in ("ff-ff-ff-ff-ff-ff", "ff:ff:ff:ff:ff:ff"):
                continue

            try:
                mac = normalize_mac(mac_raw)
            except ValueError:
                continue

            # Skip multicast MACs (first byte odd)
            first_byte = int(mac[:2], 16)
            if first_byte & 0x01:
                continue

            if mac in seen_macs:
                continue
            seen_macs.add(mac)

            device = NetworkDevice(
                ip_address=ip,
                mac_address=mac,
                interface=current_interface,
                arp_type=arp_type,
            )
            devices.append(device)

    return devices


def _resolve_hostname(ip_address: str) -> Optional[str]:
    """Attempt to resolve an IP address to a hostname.

    Tries reverse DNS lookup. On failure, returns None.

    Args:
        ip_address: IP address to resolve.

    Returns:
        Hostname string, or None if resolution fails.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        if hostname and hostname != ip_address:
            return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass

    return None
