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
    signal_dbm: float | None
    radio_type: str
    channel: int
    vendor: str | None = None
    is_randomized: bool = False
    device_name: str | None = None
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
        raise RuntimeError("WiFi scanning requires Windows (netsh not found).") from None
    except subprocess.TimeoutExpired:
        logger.error("WiFi scan timed out after 30 seconds.")
        raise RuntimeError("WiFi scan timed out.") from None

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

        field = _match_network_field(line)
        if field:
            key, value = field
            if key == "ssid":
                current_ssid = value
            elif key == "network_type":
                current_network_type = value
            elif key == "auth":
                current_auth = value
            elif key == "encryption":
                current_encryption = value
            continue

        # BSSID line — this starts a new access point entry
        bssid_match = re.match(r"^BSSID\s*\d*\s*:\s*([0-9a-f:]{17})", line, re.IGNORECASE)
        if bssid_match:
            network = _parse_bssid_entry(
                bssid_match.group(1).strip(),
                lines,
                i,
                current_ssid,
                current_network_type,
                current_auth,
                current_encryption,
            )
            if network:
                networks.append(network)

    return networks


# Regex patterns for network field parsing
_FIELD_PATTERNS: list[tuple[str, str]] = [
    ("ssid", r"^SSID\s*\d*\s*:\s*(.*)"),
    ("network_type", r"^(?:Network type|Netzwerktyp|Tipo de red)\s*:\s*(.*)"),
    ("auth", r"^(?:Authentication|Authentifizierung|Autenticaci.n)\s*:\s*(.*)"),
    ("encryption", r"^(?:Encryption|Verschl.sselung|Cifrado)\s*:\s*(.*)"),
]


def _match_network_field(line: str) -> tuple[str, str] | None:
    """Match a netsh output line against known network field patterns.

    Args:
        line: Stripped line from netsh output.

    Returns:
        Tuple of (field_key, value) if matched, None otherwise.
    """
    if line.upper().startswith("BSSID"):
        return None

    for key, pattern in _FIELD_PATTERNS:
        match = re.match(pattern, line, re.IGNORECASE)
        if match:
            return (key, match.group(1).strip())
    return None


def _parse_bssid_entry(
    bssid: str,
    lines: list[str],
    line_index: int,
    ssid: str,
    network_type: str,
    auth: str,
    encryption: str,
) -> WifiNetwork | None:
    """Parse a BSSID entry with lookahead for signal/radio/channel.

    Args:
        bssid: Raw BSSID string.
        lines: All output lines.
        line_index: Index of the BSSID line.
        ssid: Current SSID context.
        network_type: Current network type.
        auth: Current authentication mode.
        encryption: Current encryption mode.

    Returns:
        WifiNetwork if valid, None if BSSID is invalid.
    """
    signal_percent, radio_type, channel = _lookahead_bssid_details(lines, line_index)

    try:
        normalized_bssid = normalize_mac(bssid)
    except ValueError:
        logger.warning("Skipping invalid BSSID: %s", bssid)
        return None

    return WifiNetwork(
        ssid=ssid or "<Hidden>",
        bssid=normalized_bssid,
        network_type=network_type,
        authentication=auth,
        encryption=encryption,
        signal_percent=signal_percent,
        signal_dbm=signal_percent_to_dbm(signal_percent),
        radio_type=radio_type,
        channel=channel,
    )


def _lookahead_bssid_details(lines: list[str], bssid_index: int) -> tuple[int, str, int]:
    """Look ahead after a BSSID line to extract signal, radio type, channel.

    Args:
        lines: All output lines.
        bssid_index: Index of the BSSID line.

    Returns:
        Tuple of (signal_percent, radio_type, channel).
    """
    signal_percent = 0
    radio_type = ""
    channel = 0

    for j in range(bssid_index + 1, min(bssid_index + 6, len(lines))):
        ahead = lines[j].strip()

        if re.match(r"^(?:SSID|BSSID)\s", ahead, re.IGNORECASE):
            break

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

    return signal_percent, radio_type, channel


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
