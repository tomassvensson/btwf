"""BtWiFi — Main entry point for the device visibility tracker.

Scans for WiFi networks, Bluetooth devices, and local network devices,
then stores results in the database and displays a human-readable table.
"""

import logging
import sys
from datetime import datetime, timezone

from tabulate import tabulate

from src.bluetooth_scanner import scan_bluetooth_devices
from src.database import get_session, init_database
from src.device_tracker import (
    get_all_devices_with_latest_window,
    track_bluetooth_scan,
    track_wifi_scan,
    upsert_wifi_device,
    update_visibility,
)
from src.models import Device
from src.network_discovery import scan_arp_table
from src.oui_lookup import is_randomized_mac, lookup_vendor, normalize_mac
from src.wifi_scanner import scan_wifi_networks

# Translate verbose vendor names into friendlier brand names
_FRIENDLY_VENDOR_NAMES: dict[str, str] = {
    "ASUSTek COMPUTER INC.": "ASUS",
    "Zyxel Communications Corporation": "Zyxel",
    "FN-LINK TECHNOLOGY Ltd.": "FN-Link Technology",
    "Synology Incorporated": "Synology",
    "Hon Hai Precision Ind. Co.,Ltd.": "Foxconn (Hon Hai)",
    "Espressif Inc.": "Espressif (ESP)",
    "Tuya Smart Inc.": "Tuya Smart",
    "Google, Inc.": "Google",
    "BSH Hausgeräte GmbH": "Bosch/Siemens",
    "Earda Technologies co Ltd": "Earda Technologies",
    "Microsoft Corporation": "Microsoft",
    "Apple, Inc.": "Apple",
    "Samsung Electronics Co.,Ltd": "Samsung",
    "Huawei Technologies Co.,Ltd": "Huawei",
    "Intel Corporate": "Intel",
    "Qualcomm Inc.": "Qualcomm",
    "TP-LINK TECHNOLOGIES CO.,LTD.": "TP-Link",
    "NETGEAR": "Netgear",
    "Xiaomi Communications Co Ltd": "Xiaomi",
    "Raspberry Pi Trading Ltd": "Raspberry Pi",
    "Amazon Technologies Inc.": "Amazon",
    "Sony Interactive Entertainment Inc.": "Sony",
    "LG Electronics (Mobile Communications)": "LG Electronics",
    "Murata Manufacturing Co., Ltd.": "Murata",
    "Texas Instruments": "Texas Instruments",
    "Broadcom": "Broadcom",
    "Realtek Semiconductor Corp.": "Realtek",
    "MediaTek Inc.": "MediaTek",
    "Dell Inc.": "Dell",
    "Hewlett Packard": "HP",
    "Lenovo": "Lenovo",
}


def _friendly_vendor(vendor: str | None, mac: str) -> str:
    """Return a human-friendly vendor name, noting randomized MACs.

    Args:
        vendor: Raw vendor string from OUI database.
        mac: MAC address of the device.

    Returns:
        Friendly vendor string for display.
    """
    if vendor:
        display = _FRIENDLY_VENDOR_NAMES.get(vendor, vendor)
        return display

    try:
        if is_randomized_mac(mac):
            return "(Randomized MAC)"
    except ValueError:
        pass

    return "(Unknown vendor)"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _format_signal(signal_dbm: float | None) -> str:
    """Format signal strength for display.

    Args:
        signal_dbm: Signal in dBm, or None.

    Returns:
        Human-readable signal string.
    """
    if signal_dbm is None:
        return "N/A"
    if signal_dbm >= -50:
        quality = "Excellent"
    elif signal_dbm >= -60:
        quality = "Good"
    elif signal_dbm >= -70:
        quality = "Fair"
    elif signal_dbm >= -80:
        quality = "Weak"
    else:
        quality = "Very Weak"
    return f"{signal_dbm:.0f} dBm ({quality})"


def _format_time(dt: datetime | None) -> str:
    """Format a datetime for display.

    Args:
        dt: Datetime to format.

    Returns:
        Formatted string.
    """
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _best_name(device: Device) -> str:
    """Get the best human-readable name for a device.

    Args:
        device: Device record.

    Returns:
        Best available name.
    """
    if device.device_name:
        return device.device_name
    if device.ssid and device.ssid != "<Hidden>":
        return device.ssid
    if device.vendor:
        friendly = _FRIENDLY_VENDOR_NAMES.get(device.vendor, device.vendor)
        return f"{friendly} device"
    return device.mac_address


def run_scan() -> None:
    """Run a complete scan cycle: WiFi, Bluetooth, and ARP discovery."""
    logger.info("=" * 60)
    logger.info("BtWiFi Device Visibility Tracker — Starting scan")
    logger.info("=" * 60)

    # Initialize database
    engine = init_database()

    # ---- WiFi Scan ----
    wifi_networks = []
    try:
        wifi_networks = scan_wifi_networks()
    except RuntimeError as exc:
        logger.error("WiFi scan failed: %s", exc)

    # ---- Bluetooth Scan ----
    bt_devices = []
    try:
        bt_devices = scan_bluetooth_devices()
    except RuntimeError as exc:
        logger.error("Bluetooth scan failed: %s", exc)

    # ---- ARP / Network Discovery ----
    arp_devices = []
    try:
        arp_devices = scan_arp_table()
    except Exception as exc:
        logger.error("ARP scan failed: %s", exc)

    # ---- Store results ----
    with get_session(engine) as session:
        # Track WiFi
        wifi_results = track_wifi_scan(session, wifi_networks)
        logger.info("Tracked %d WiFi networks.", len(wifi_results))

        # Track Bluetooth
        bt_results = track_bluetooth_scan(session, bt_devices)
        logger.info("Tracked %d Bluetooth devices.", len(bt_results))

        # Track ARP devices (as wifi_client type since they're on the network)
        for arp_dev in arp_devices:
            existing = session.query(Device).filter_by(mac_address=arp_dev.mac_address).first()
            if existing is None:
                device = Device(
                    mac_address=arp_dev.mac_address,
                    device_type="network",
                    vendor=arp_dev.vendor,
                    device_name=arp_dev.hostname,
                    extra_info=f"IP: {arp_dev.ip_address}",
                )
                session.add(device)
            else:
                existing.device_name = arp_dev.hostname or existing.device_name
                existing.vendor = arp_dev.vendor or existing.vendor
                if arp_dev.ip_address:
                    existing.extra_info = f"IP: {arp_dev.ip_address}"

            update_visibility(
                session,
                mac_address=arp_dev.mac_address,
                scan_time=arp_dev.scan_time,
            )

        # Flush to ensure all data is written
        session.flush()

        # ---- Display results ----
        _display_results(session)


def _display_results(session: "Session") -> None:  # noqa: F821
    """Display all tracked devices in a human-readable table.

    Args:
        session: Active database session.
    """
    results = get_all_devices_with_latest_window(session)

    if not results:
        print("\nNo devices found.")
        return

    # Build table data
    headers = [
        "Type",
        "Name / SSID",
        "Vendor",
        "MAC Address",
        "Signal",
        "First Seen",
        "Last Seen",
        "Details",
    ]

    rows = []
    for device, window in results:
        type_label = {
            "wifi_ap": "WiFi AP",
            "wifi_client": "WiFi Client",
            "bluetooth": "Bluetooth",
            "network": "Network",
        }.get(device.device_type, device.device_type)

        name = _best_name(device)
        vendor = _friendly_vendor(device.vendor, device.mac_address)
        mac = device.mac_address

        signal = _format_signal(window.signal_strength_dbm if window else None)
        first_seen = _format_time(window.first_seen if window else None)
        last_seen = _format_time(window.last_seen if window else None)

        details_parts = []
        if device.authentication and device.authentication != "Open":
            details_parts.append(f"Auth: {device.authentication}")
        if device.encryption and device.encryption != "None":
            details_parts.append(f"Enc: {device.encryption}")
        if device.radio_type:
            details_parts.append(device.radio_type)
        if device.channel:
            details_parts.append(f"Ch {device.channel}")
        if device.extra_info:
            details_parts.append(device.extra_info)

        details = " | ".join(details_parts) if details_parts else ""

        rows.append([type_label, name, vendor, mac, signal, first_seen, last_seen, details])

    print("\n" + "=" * 120)
    print("  DISCOVERED DEVICES")
    print("=" * 120)
    print(tabulate(rows, headers=headers, tablefmt="grid"))
    print(f"\nTotal devices: {len(rows)}")
    print(f"  WiFi APs:         {sum(1 for r in rows if r[0] == 'WiFi AP')}")
    print(f"  Bluetooth:        {sum(1 for r in rows if r[0] == 'Bluetooth')}")
    print(f"  Network devices:  {sum(1 for r in rows if r[0] == 'Network')}")
    print()


def main() -> None:
    """Main entry point."""
    try:
        run_scan()
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user.")
        sys.exit(0)
    except Exception:
        logger.exception("Fatal error during scan.")
        sys.exit(1)


if __name__ == "__main__":
    main()
