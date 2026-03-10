"""mDNS / Bonjour / Avahi device discovery using zeroconf.

Discovers devices advertising services via mDNS (multicast DNS),
commonly used by printers, IoT devices, Apple devices, etc.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.oui_lookup import is_randomized_mac, lookup_vendor

logger = logging.getLogger(__name__)

# Common mDNS service types to browse
_SERVICE_TYPES: list[str] = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_ssh._tcp.local.",
    "_sftp-ssh._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_companion-link._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_matter._tcp.local.",
    "_esphomelib._tcp.local.",
    "_spotify-connect._tcp.local.",
]

# Timeout for mDNS browsing in seconds
_BROWSE_TIMEOUT = 5.0


@dataclass
class MdnsDevice:
    """A device discovered via mDNS service browsing."""

    hostname: str
    ip_address: str
    mac_address: str = ""
    service_type: str = ""
    service_name: str = ""
    port: int = 0
    vendor: str | None = None
    is_randomized: bool = False
    txt_records: dict[str, str] = field(default_factory=dict)
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def scan_mdns_services(timeout: float = _BROWSE_TIMEOUT) -> list[MdnsDevice]:
    """Discover devices advertising mDNS services on the local network.

    Uses zeroconf to browse for common service types and collect
    device information.

    Args:
        timeout: How long to browse for each service type (seconds).

    Returns:
        List of discovered MdnsDevice objects.
    """
    try:
        from zeroconf import Zeroconf
    except ImportError:
        logger.warning("zeroconf not installed. Install with: pip install zeroconf")
        return []

    logger.info("Starting mDNS service discovery (timeout=%.1fs per type)...", timeout)
    seen_keys: set[str] = set()

    zc = Zeroconf()
    try:
        collector = _ServiceCollector()
        browsers = _start_browsers(zc, collector)

        import time

        time.sleep(timeout)

        devices = _process_collected_services(zc, collector, seen_keys, timeout)

        for browser in browsers:
            browser.cancel()
    finally:
        zc.close()

    logger.info("mDNS discovery complete: found %d services.", len(devices))
    return devices


def _start_browsers(zc: Any, collector: "_ServiceCollector") -> list[Any]:
    """Start ServiceBrowser instances for all known service types.

    Args:
        zc: Zeroconf instance.
        collector: Service collector listener.

    Returns:
        List of active ServiceBrowser instances.
    """
    from zeroconf import ServiceBrowser

    browsers: list[Any] = []
    for stype in _SERVICE_TYPES:
        try:
            browser = ServiceBrowser(zc, stype, collector)  # type: ignore[arg-type]
            browsers.append(browser)
        except Exception:
            logger.debug("Failed to browse service type: %s", stype)
    return browsers


def _process_collected_services(
    zc: Any,
    collector: "_ServiceCollector",
    seen_keys: set[str],
    timeout: float,
) -> list[MdnsDevice]:
    """Process services collected by the listener into MdnsDevice objects.

    Args:
        zc: Zeroconf instance.
        collector: Service collector with found services.
        seen_keys: Set for deduplication by IP+service.
        timeout: Timeout for service info resolution.

    Returns:
        List of discovered MdnsDevice objects.
    """
    devices: list[MdnsDevice] = []

    for stype, name in collector.found:
        device = _resolve_service(zc, stype, name, seen_keys, timeout)
        if device:
            devices.append(device)

    return devices


def _resolve_service(
    zc: Any,
    stype: str,
    name: str,
    seen_keys: set[str],
    timeout: float,
) -> MdnsDevice | None:
    """Resolve a single mDNS service into an MdnsDevice.

    Args:
        zc: Zeroconf instance.
        stype: Service type string.
        name: Service name.
        seen_keys: Set for deduplication.
        timeout: Resolution timeout.

    Returns:
        MdnsDevice if resolved, None otherwise.
    """
    try:
        info = zc.get_service_info(stype, name, timeout=int(timeout * 1000))
        if info is None:
            return None

        addresses = info.parsed_addresses()
        if not addresses:
            return None

        ip = addresses[0]
        key = f"{ip}:{stype}"
        if key in seen_keys:
            return None
        seen_keys.add(key)

        mac = _arp_lookup_mac(ip)
        txt = _parse_txt_records(info.properties)
        vendor = lookup_vendor(mac) if mac else None
        is_rand = is_randomized_mac(mac) if mac else False

        return MdnsDevice(
            hostname=(info.server or "").rstrip("."),
            ip_address=ip,
            mac_address=mac,
            service_type=stype.replace("._tcp.local.", "").lstrip("_"),
            service_name=name,
            port=info.port or 0,
            vendor=vendor,
            is_randomized=is_rand,
            txt_records=txt,
        )
    except Exception:
        logger.debug("Failed to resolve mDNS service: %s", name)
        return None


def _parse_txt_records(properties: dict[bytes, bytes | None] | None) -> dict[str, str]:
    """Parse mDNS TXT record properties into a string dictionary.

    Args:
        properties: Raw TXT record properties from zeroconf.

    Returns:
        Parsed key-value dictionary.
    """
    txt: dict[str, str] = {}
    if not properties:
        return txt

    for key_bytes, val_bytes in properties.items():
        try:
            k = key_bytes.decode("utf-8", errors="replace") if isinstance(key_bytes, bytes) else str(key_bytes)
            v = val_bytes.decode("utf-8", errors="replace") if isinstance(val_bytes, bytes) else str(val_bytes or "")
            txt[k] = v
        except Exception:
            pass

    return txt


class _ServiceCollector:
    """Collects mDNS service discoveries.

    Implements the zeroconf ServiceListener interface.
    """

    def __init__(self) -> None:
        self.found: list[tuple[str, str]] = []

    def add_service(self, zc: object, type_: str, name: str) -> None:  # noqa: ARG002  # NOSONAR python:S1172 - required by ServiceListener interface
        """Handle a newly discovered service."""
        self.found.append((type_, name))

    def remove_service(self, zc: object, type_: str, name: str) -> None:  # noqa: ARG002  # NOSONAR python:S1172 - required by ServiceListener interface
        """Handle a removed service (ignored)."""

    def update_service(self, zc: object, type_: str, name: str) -> None:  # noqa: ARG002  # NOSONAR python:S1172 - required by ServiceListener interface
        """Handle a service update (treated as add)."""
        self.found.append((type_, name))


def _arp_lookup_mac(ip_address: str) -> str:
    """Look up a MAC address from the ARP cache for a given IP.

    Args:
        ip_address: IP address to look up.

    Returns:
        MAC address string (normalized), or empty string if not found.
    """
    import re
    import subprocess

    try:
        result = subprocess.run(
            ["arp", "-a", ip_address],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            # Match MAC in arp output
            match = re.search(
                r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})",
                result.stdout,
            )
            if match:
                from src.oui_lookup import normalize_mac

                return normalize_mac(match.group(1))
    except Exception:
        pass

    return ""
