"""Device categorization engine.

Automatically categorizes devices based on vendor names, hostnames,
MAC OUI prefixes, and other identifying markers.
"""

import logging
import re

logger = logging.getLogger(__name__)

# Category constants
CATEGORY_ROUTER = "router"
CATEGORY_AP = "access_point"
CATEGORY_NAS = "nas"
CATEGORY_PRINTER = "printer"
CATEGORY_COMPUTER = "computer"
CATEGORY_MOBILE = "mobile"
CATEGORY_TABLET = "tablet"
CATEGORY_IOT = "iot"
CATEGORY_TV = "tv"
CATEGORY_GAMING = "gaming"
CATEGORY_WEARABLE = "wearable"
CATEGORY_CAMERA = "camera"
CATEGORY_SPEAKER = "speaker"
CATEGORY_APPLIANCE = "appliance"
CATEGORY_NETWORK = "network"
CATEGORY_VIRTUAL = "virtual"
CATEGORY_UNKNOWN = "unknown"

# Human-readable labels for categories
CATEGORY_LABELS: dict[str, str] = {
    CATEGORY_ROUTER: "Router/Gateway",
    CATEGORY_AP: "Access Point",
    CATEGORY_NAS: "NAS",
    CATEGORY_PRINTER: "Printer",
    CATEGORY_COMPUTER: "Computer",
    CATEGORY_MOBILE: "Mobile Phone",
    CATEGORY_TABLET: "Tablet",
    CATEGORY_IOT: "IoT Device",
    CATEGORY_TV: "TV/Media",
    CATEGORY_GAMING: "Gaming",
    CATEGORY_WEARABLE: "Wearable",
    CATEGORY_CAMERA: "Camera",
    CATEGORY_SPEAKER: "Speaker",
    CATEGORY_APPLIANCE: "Appliance",
    CATEGORY_NETWORK: "Network Device",
    CATEGORY_VIRTUAL: "Virtual Machine",
    CATEGORY_UNKNOWN: "Unknown",
}

# Patterns for vendor-based categorization (case-insensitive)
_VENDOR_CATEGORY_RULES: list[tuple[str, str]] = [
    # NAS
    (r"synology", CATEGORY_NAS),
    (r"qnap", CATEGORY_NAS),
    (r"western\s*digital.*nas", CATEGORY_NAS),
    (r"netgear.*readynas", CATEGORY_NAS),
    # Routers / APs
    (r"asus.*router|asus.*zen\s*wifi|asus.*rt-", CATEGORY_ROUTER),
    (r"zyxel", CATEGORY_ROUTER),
    (r"tp-?link", CATEGORY_ROUTER),
    (r"netgear", CATEGORY_ROUTER),
    (r"linksys", CATEGORY_ROUTER),
    (r"d-?link", CATEGORY_ROUTER),
    (r"ubiquiti|unifi", CATEGORY_AP),
    (r"aruba", CATEGORY_AP),
    (r"cisco.*meraki", CATEGORY_AP),
    (r"mikrotik", CATEGORY_ROUTER),
    # Printers
    (r"brother", CATEGORY_PRINTER),
    (r"canon\b.*print", CATEGORY_PRINTER),
    (r"epson", CATEGORY_PRINTER),
    (r"hewlett.*packard|hp\b", CATEGORY_PRINTER),
    (r"lexmark", CATEGORY_PRINTER),
    (r"xerox", CATEGORY_PRINTER),
    (r"hon\s*hai|foxconn", CATEGORY_PRINTER),
    # Mobile
    (r"apple", CATEGORY_MOBILE),
    (r"samsung.*mobile|samsung.*galaxy", CATEGORY_MOBILE),
    (r"huawei.*mobile", CATEGORY_MOBILE),
    (r"xiaomi", CATEGORY_MOBILE),
    (r"oneplus", CATEGORY_MOBILE),
    (r"oppo", CATEGORY_MOBILE),
    (r"vivo\b", CATEGORY_MOBILE),
    (r"motorola", CATEGORY_MOBILE),
    (r"nokia\b.*mobile", CATEGORY_MOBILE),
    # TV / Media
    (r"samsung.*tv|samsung.*electronics", CATEGORY_TV),
    (r"lg.*electronics", CATEGORY_TV),
    (r"sony", CATEGORY_TV),
    (r"roku", CATEGORY_TV),
    (r"earda", CATEGORY_TV),
    (r"chromecast", CATEGORY_TV),
    # IoT
    (r"tuya", CATEGORY_IOT),
    (r"espressif|esp\b", CATEGORY_IOT),
    (r"shelly", CATEGORY_IOT),
    (r"sonoff", CATEGORY_IOT),
    (r"philips.*hue", CATEGORY_IOT),
    (r"ikea.*tradfri", CATEGORY_IOT),
    (r"ring\b", CATEGORY_IOT),
    (r"nest\b", CATEGORY_IOT),
    (r"bosch.*siemens|bsh", CATEGORY_IOT),
    # Speakers
    (r"sonos", CATEGORY_SPEAKER),
    (r"amazon.*echo", CATEGORY_SPEAKER),
    (r"google.*home|google.*nest", CATEGORY_SPEAKER),
    # Gaming
    (r"nintendo", CATEGORY_GAMING),
    (r"sony.*playstation|sony.*interactive", CATEGORY_GAMING),
    (r"microsoft.*xbox", CATEGORY_GAMING),
    (r"valve\b", CATEGORY_GAMING),
    # Cameras
    (r"hikvision", CATEGORY_CAMERA),
    (r"dahua", CATEGORY_CAMERA),
    (r"reolink", CATEGORY_CAMERA),
    (r"wyze", CATEGORY_CAMERA),
    # Computers
    (r"dell\b", CATEGORY_COMPUTER),
    (r"lenovo", CATEGORY_COMPUTER),
    (r"intel\b", CATEGORY_COMPUTER),
    (r"realtek", CATEGORY_COMPUTER),
    (r"broadcom", CATEGORY_COMPUTER),
    (r"qualcomm", CATEGORY_COMPUTER),
    (r"mediatek", CATEGORY_COMPUTER),
    (r"fn-?link", CATEGORY_COMPUTER),
    # Network
    (r"microsoft\b", CATEGORY_NETWORK),
    # Virtual
    (r"hyper-?v", CATEGORY_VIRTUAL),
    (r"vmware", CATEGORY_VIRTUAL),
    (r"virtualbox", CATEGORY_VIRTUAL),
]

# Patterns for hostname-based categorization (case-insensitive)
_HOSTNAME_CATEGORY_RULES: list[tuple[str, str]] = [
    (r"iphone", CATEGORY_MOBILE),
    (r"ipad", CATEGORY_TABLET),
    (r"android", CATEGORY_MOBILE),
    (r"galaxy", CATEGORY_MOBILE),
    (r"pixel\b", CATEGORY_MOBILE),
    (r"macbook", CATEGORY_COMPUTER),
    (r"imac\b", CATEGORY_COMPUTER),
    (r"mac\s*mini", CATEGORY_COMPUTER),
    (r"mac\s*pro", CATEGORY_COMPUTER),
    (r"desktop|laptop|workstation|pc\b", CATEGORY_COMPUTER),
    (r"brw[0-9a-f]|brother|printer|print", CATEGORY_PRINTER),
    (r"nas\b|synology|diskstation|ds-?tom|cloud\d", CATEGORY_NAS),
    (r"router|gateway", CATEGORY_ROUTER),
    (r"switch\b|managed.*switch", CATEGORY_NETWORK),
    (r"tv\b|television|smart\s*tv|fire\s*tv|roku|chromecast|apple\s*tv", CATEGORY_TV),
    (r"hub|mini.*hub|tv.*hub", CATEGORY_TV),
    (r"esp[-_]|esp8266|esp32|nodemcu|wlan0", CATEGORY_IOT),
    (r"docker|vm\b|hyper-?v|wsl\b", CATEGORY_VIRTUAL),
    (r"xbox|playstation|nintendo|switch\b", CATEGORY_GAMING),
    (r"echo|alexa|google.*home|homepod", CATEGORY_SPEAKER),
    (r"cam\b|camera|doorbell", CATEGORY_CAMERA),
    (r"watch\b|band\b|fitbit|garmin", CATEGORY_WEARABLE),
    (r"zen\s*wifi|mesh|extender|repeater|access.*point", CATEGORY_AP),
]

# MAC OUI prefix-based categorization (first 3 bytes)
_OUI_CATEGORY_MAP: dict[str, str] = {
    "00:15:5D": CATEGORY_VIRTUAL,  # Microsoft Hyper-V
    "00:50:56": CATEGORY_VIRTUAL,  # VMware
    "00:0C:29": CATEGORY_VIRTUAL,  # VMware
    "08:00:27": CATEGORY_VIRTUAL,  # VirtualBox
}


def categorize_device(
    vendor: str | None = None,
    hostname: str | None = None,
    device_name: str | None = None,
    ssid: str | None = None,
    mac_address: str | None = None,
    device_type: str | None = None,
) -> str:
    """Categorize a device based on available information.

    Uses a priority-based approach:
    1. MAC OUI prefix (most reliable for VMs)
    2. Hostname patterns
    3. Device name patterns
    4. SSID patterns
    5. Vendor name patterns
    6. Device type fallback

    Args:
        vendor: Vendor/manufacturer name.
        hostname: Resolved hostname.
        device_name: Device friendly name.
        ssid: WiFi SSID.
        mac_address: MAC address.
        device_type: Device type string (wifi_ap, bluetooth, etc.).

    Returns:
        Category string constant.
    """
    # 1. Check MAC OUI prefix
    if mac_address and len(mac_address) >= 8:
        prefix = mac_address[:8].upper()
        if prefix in _OUI_CATEGORY_MAP:
            return _OUI_CATEGORY_MAP[prefix]

    # 2. Check hostname
    if hostname:
        cat = _match_rules(hostname, _HOSTNAME_CATEGORY_RULES)
        if cat:
            return cat

    # 3. Check device name
    if device_name:
        cat = _match_rules(device_name, _HOSTNAME_CATEGORY_RULES)
        if cat:
            return cat

    # 4. Check SSID
    if ssid:
        cat = _match_rules(ssid, _HOSTNAME_CATEGORY_RULES)
        if cat:
            return cat

    # 5. Check vendor
    if vendor:
        cat = _match_rules(vendor, _VENDOR_CATEGORY_RULES)
        if cat:
            return cat

    # 6. Device type fallback
    if device_type == "wifi_ap":
        return CATEGORY_AP
    if device_type == "bluetooth":
        return CATEGORY_NETWORK

    return CATEGORY_UNKNOWN


def get_category_label(category: str) -> str:
    """Get a human-readable label for a category.

    Args:
        category: Category constant.

    Returns:
        Human-readable label string.
    """
    return CATEGORY_LABELS.get(category, category.replace("_", " ").title())


def _match_rules(text: str, rules: list[tuple[str, str]]) -> str | None:
    """Match text against a list of regex->category rules.

    Args:
        text: Text to match.
        rules: List of (regex_pattern, category) tuples.

    Returns:
        Matching category, or None.
    """
    for pattern, category in rules:
        if re.search(pattern, text, re.IGNORECASE):
            return category
    return None
