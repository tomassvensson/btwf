"""Bluetooth device scanner for Windows.

Uses PowerShell to query Windows Bluetooth APIs for nearby devices.
Falls back to WMI queries if the primary method fails.

Security: This is purely passive scanning — no pairing or connections
are established with discovered devices.
"""

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from src.oui_lookup import is_randomized_mac, lookup_vendor, normalize_mac

logger = logging.getLogger(__name__)


@dataclass
class BluetoothDevice:
    """A discovered Bluetooth device."""

    mac_address: str
    device_name: Optional[str] = None
    is_connected: bool = False
    is_paired: bool = False
    device_class: Optional[str] = None
    vendor: Optional[str] = None
    is_randomized: bool = False
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Post-initialization: look up vendor and check for randomization."""
        if self.vendor is None and self.mac_address:
            self.vendor = lookup_vendor(self.mac_address)
        if self.mac_address:
            self.is_randomized = is_randomized_mac(self.mac_address)


# PowerShell script to discover Bluetooth devices via PnP / WMI
_BT_DISCOVERY_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$devices = @()

# Method 1: Get-PnpDevice for Bluetooth devices
$btDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -and $_.InstanceId -match 'BTHENUM|BTH' }

foreach ($dev in $btDevices) {
    $instanceId = $dev.InstanceId
    $mac = ''

    # Extract MAC from InstanceId (format: BTHENUM\...\XX:XX:XX:XX:XX:XX or similar)
    if ($instanceId -match '([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}') {
        $mac = $matches[0]
    } elseif ($instanceId -match '([0-9A-Fa-f]{12})') {
        $raw = $matches[1]
        $mac = ($raw -replace '(.{2})', '$1:').TrimEnd(':')
    }

    $devices += @{
        Name = $dev.FriendlyName
        MAC = $mac
        Status = $dev.Status
        Class = $dev.Class
        InstanceId = $instanceId
    }
}

# Method 2: WMI Bluetooth devices
$wmiDevices = Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
    Where-Object { $_.PNPClass -eq 'Bluetooth' -or $_.Name -match 'Bluetooth' }

foreach ($dev in $wmiDevices) {
    $instanceId = $dev.DeviceID
    $mac = ''

    if ($instanceId -match '([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}') {
        $mac = $matches[0]
    } elseif ($instanceId -match '_([0-9A-Fa-f]{12})') {
        $raw = $matches[1]
        $mac = ($raw -replace '(.{2})', '$1:').TrimEnd(':')
    }

    # Avoid duplicates
    $existing = $devices | Where-Object { $_.MAC -eq $mac -and $mac -ne '' }
    if (-not $existing -and $mac) {
        $devices += @{
            Name = $dev.Name
            MAC = $mac
            Status = $dev.Status
            Class = 'Bluetooth'
            InstanceId = $instanceId
        }
    }
}

$devices | ConvertTo-Json -Depth 3
"""


def scan_bluetooth_devices() -> list[BluetoothDevice]:
    """Scan for nearby/known Bluetooth devices using Windows APIs.

    Returns:
        List of discovered BluetoothDevice objects.

    Raises:
        RuntimeError: If the scan fails completely.
    """
    logger.info("Starting Bluetooth device scan...")

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", _BT_DISCOVERY_SCRIPT],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        logger.error("PowerShell not found. Bluetooth scanning requires Windows.")
        raise RuntimeError("Bluetooth scanning requires Windows PowerShell.")
    except subprocess.TimeoutExpired:
        logger.error("Bluetooth scan timed out after 30 seconds.")
        raise RuntimeError("Bluetooth scan timed out.")

    if result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else ""
        logger.warning("Bluetooth scan had warnings: %s", stderr)

    return _parse_bt_output(result.stdout)


def _parse_bt_output(output: str) -> list[BluetoothDevice]:
    """Parse the JSON output from the PowerShell Bluetooth scan.

    Args:
        output: JSON string from PowerShell script.

    Returns:
        List of BluetoothDevice objects.
    """
    output = output.strip()
    if not output:
        logger.info("No Bluetooth devices found.")
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        logger.warning("Failed to parse Bluetooth scan output as JSON.")
        logger.debug("Raw output: %s", output[:500])
        return []

    # Ensure we have a list
    if isinstance(data, dict):
        data = [data]

    devices: list[BluetoothDevice] = []
    seen_macs: set[str] = set()

    for item in data:
        if not isinstance(item, dict):
            continue

        mac = item.get("MAC", "")
        name = item.get("Name", "")
        status = item.get("Status", "")

        # Skip entries without a MAC or name
        if not mac and not name:
            continue

        # Skip the Bluetooth adapter itself (often named "Intel Wireless Bluetooth" or similar)
        if _is_bluetooth_adapter(name):
            logger.debug("Skipping Bluetooth adapter: %s", name)
            continue

        # Normalize MAC if available
        if mac:
            try:
                mac = normalize_mac(mac)
            except ValueError:
                logger.debug("Skipping device with invalid MAC: %s", mac)
                continue

            if mac in seen_macs:
                continue
            seen_macs.add(mac)

        device = BluetoothDevice(
            mac_address=mac,
            device_name=name or None,
            is_connected=(status == "OK"),
            is_paired=True,  # PnP devices are typically paired
            device_class=item.get("Class"),
        )
        devices.append(device)

    logger.info("Bluetooth scan complete: found %d devices.", len(devices))
    return devices


def _is_bluetooth_adapter(name: str) -> bool:
    """Check if a device name indicates it's the local Bluetooth adapter.

    Args:
        name: Device friendly name.

    Returns:
        True if this appears to be the local adapter, not a remote device.
    """
    adapter_patterns = [
        r"(?i)bluetooth.*adapter",
        r"(?i)bluetooth.*radio",
        r"(?i)generic.*bluetooth.*adapter",
        r"(?i)intel.*wireless.*bluetooth$",
        r"(?i)realtek.*bluetooth.*adapter",
        r"(?i)qualcomm.*bluetooth.*adapter",
        r"(?i)broadcom.*bluetooth.*adapter",
        r"(?i)microsoft.*bluetooth.*enumerator",
    ]
    return any(re.search(pattern, name) for pattern in adapter_patterns)
