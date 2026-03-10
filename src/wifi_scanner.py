"""WiFi network and device scanner using Windows netsh commands.

This module scans for nearby WiFi networks by parsing the output of
`netsh wlan show networks mode=bssid`. It works on Windows without
any additional drivers or libraries.

Security: This is purely passive scanning. No connections are established
with discovered networks/devices.
"""

import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from src.oui_lookup import is_randomized_mac, lookup_vendor, normalize_mac

logger = logging.getLogger(__name__)


@dataclass
class WifiNetwork:
    """A discovered WiFi network / access point."""

    ssid: str
    bssid: str  # MAC address of the access point
    network_type: str
    authentication: str
    encryption: str
    signal_percent: int
    signal_dbm: Optional[float]
    radio_type: str
    channel: int
    vendor: Optional[str] = None
    is_randomized: bool = False
    device_name: Optional[str] = None
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Post-initialization: look up vendor and check for randomization."""
        if self.vendor is None:
            self.vendor = lookup_vendor(self.bssid)
        self.is_randomized = is_randomized_mac(self.bssid)


def signal_percent_to_dbm(percent: int) -> float:
    """Convert Windows signal strength percentage to approximate dBm.

    Windows reports signal as a percentage (0-100). This converts to
    approximate dBm using the common linear mapping:
    dBm = (percent / 2) - 100

    Args:
        percent: Signal strength as percentage (0-100).

    Returns:
        Approximate signal strength in dBm.
    """
    percent = max(0, min(100, percent))
    return (percent / 2) - 100


def scan_wifi_networks() -> list[WifiNetwork]:
    """Scan for nearby WiFi networks using netsh.

    Returns:
        List of discovered WifiNetwork objects.

    Raises:
        RuntimeError: If the netsh command fails.
    """
    logger.info("Starting WiFi network scan...")
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        logger.error("netsh command not found. WiFi scanning requires Windows.")
        raise RuntimeError("WiFi scanning requires Windows (netsh not found).")
    except subprocess.TimeoutExpired:
        logger.error("WiFi scan timed out after 30 seconds.")
        raise RuntimeError("WiFi scan timed out.")

    if result.returncode != 0:
        error_msg = result.stderr.strip() if result.stderr else "Unknown error"
        logger.error("netsh failed (rc=%d): %s", result.returncode, error_msg)
        raise RuntimeError(f"WiFi scan failed: {error_msg}")

    networks = _parse_netsh_output(result.stdout)
    logger.info("WiFi scan complete: found %d networks/access points.", len(networks))
    return networks


def _parse_netsh_output(output: str) -> list[WifiNetwork]:
    """Parse the output of `netsh wlan show networks mode=bssid`.

    Handles both English and other locale outputs by looking for
    patterns in the structure rather than exact label matches.

    Args:
        output: Raw stdout from netsh command.

    Returns:
        List of WifiNetwork objects.
    """
    networks: list[WifiNetwork] = []
    current_ssid = ""
    current_network_type = ""
    current_auth = ""
    current_encryption = ""

    lines = output.splitlines()

    for i, line in enumerate(lines):
        line = line.strip()

        # SSID line (but not BSSID) — matches "SSID 1 : NetworkName" or "SSID : NetworkName"
        ssid_match = re.match(r"^SSID\s*\d*\s*:\s*(.*)", line, re.IGNORECASE)
        if ssid_match and not line.upper().startswith("BSSID"):
            current_ssid = ssid_match.group(1).strip()
            continue

        # Network type
        net_type_match = re.match(r"^(?:Network type|Netzwerktyp|Tipo de red)\s*:\s*(.*)", line, re.IGNORECASE)
        if net_type_match:
            current_network_type = net_type_match.group(1).strip()
            continue

        # Authentication
        auth_match = re.match(r"^(?:Authentication|Authentifizierung|Autenticaci.n)\s*:\s*(.*)", line, re.IGNORECASE)
        if auth_match:
            current_auth = auth_match.group(1).strip()
            continue

        # Encryption
        enc_match = re.match(r"^(?:Encryption|Verschl.sselung|Cifrado)\s*:\s*(.*)", line, re.IGNORECASE)
        if enc_match:
            current_encryption = enc_match.group(1).strip()
            continue

        # BSSID line — this starts a new access point entry
        bssid_match = re.match(r"^BSSID\s*\d*\s*:\s*([0-9a-fA-F:]{17})", line, re.IGNORECASE)
        if bssid_match:
            bssid = bssid_match.group(1).strip()

            # Look ahead for signal, radio type, and channel
            signal_percent = 0
            radio_type = ""
            channel = 0

            for j in range(i + 1, min(i + 6, len(lines))):
                ahead = lines[j].strip()

                signal_match = re.match(r"^(?:Signal|Se.al)\s*:\s*(\d+)%", ahead, re.IGNORECASE)
                if signal_match:
                    signal_percent = int(signal_match.group(1))
                    continue

                radio_match = re.match(r"^(?:Radio type|Funktyp|Tipo de radio)\s*:\s*(.*)", ahead, re.IGNORECASE)
                if radio_match:
                    radio_type = radio_match.group(1).strip()
                    continue

                channel_match = re.match(r"^(?:Channel|Kanal|Canal)\s*:\s*(\d+)", ahead, re.IGNORECASE)
                if channel_match:
                    channel = int(channel_match.group(1))
                    continue

                # Stop if we hit a new SSID or BSSID
                if re.match(r"^(?:SSID|BSSID)\s", ahead, re.IGNORECASE):
                    break

            try:
                normalized_bssid = normalize_mac(bssid)
            except ValueError:
                logger.warning("Skipping invalid BSSID: %s", bssid)
                continue

            network = WifiNetwork(
                ssid=current_ssid or "<Hidden>",
                bssid=normalized_bssid,
                network_type=current_network_type,
                authentication=current_auth,
                encryption=current_encryption,
                signal_percent=signal_percent,
                signal_dbm=signal_percent_to_dbm(signal_percent),
                radio_type=radio_type,
                channel=channel,
            )
            networks.append(network)

    return networks


def get_wifi_interfaces() -> list[dict[str, str]]:
    """Get information about available WiFi interfaces.

    Returns:
        List of dicts with interface information.
    """
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.warning("Could not query WiFi interfaces.")
        return []

    if result.returncode != 0:
        return []

    interfaces: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            if current:
                interfaces.append(current)
                current = {}
            continue

        match = re.match(r"^(.+?)\s*:\s*(.+)$", line)
        if match:
            key = match.group(1).strip()
            value = match.group(2).strip()
            current[key] = value

    if current:
        interfaces.append(current)

    return interfaces
