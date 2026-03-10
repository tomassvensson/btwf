"""Tests for device categorization engine."""

from src.categorizer import (
    CATEGORY_AP,
    CATEGORY_CAMERA,
    CATEGORY_COMPUTER,
    CATEGORY_GAMING,
    CATEGORY_IOT,
    CATEGORY_MOBILE,
    CATEGORY_NAS,
    CATEGORY_NETWORK,
    CATEGORY_PRINTER,
    CATEGORY_ROUTER,
    CATEGORY_SPEAKER,
    CATEGORY_TABLET,
    CATEGORY_TV,
    CATEGORY_UNKNOWN,
    CATEGORY_VIRTUAL,
    _match_rules,
    categorize_device,
    get_category_label,
)


class TestCategorizeByVendor:
    """Tests for vendor-based categorization."""

    def test_synology_is_nas(self) -> None:
        assert categorize_device(vendor="Synology Inc.") == CATEGORY_NAS

    def test_tp_link_is_router(self) -> None:
        assert categorize_device(vendor="TP-LINK Technologies Co.,Ltd") == CATEGORY_ROUTER

    def test_apple_is_mobile(self) -> None:
        assert categorize_device(vendor="Apple, Inc.") == CATEGORY_MOBILE

    def test_espressif_is_iot(self) -> None:
        assert categorize_device(vendor="Espressif Inc.") == CATEGORY_IOT

    def test_brother_is_printer(self) -> None:
        assert categorize_device(vendor="Brother Industries, Ltd.") == CATEGORY_PRINTER

    def test_sonos_is_speaker(self) -> None:
        assert categorize_device(vendor="Sonos, Inc.") == CATEGORY_SPEAKER

    def test_samsung_electronics_is_tv(self) -> None:
        assert categorize_device(vendor="Samsung Electronics Co.,Ltd") == CATEGORY_TV

    def test_nintendo_is_gaming(self) -> None:
        assert categorize_device(vendor="Nintendo Co.,Ltd") == CATEGORY_GAMING

    def test_hikvision_is_camera(self) -> None:
        assert categorize_device(vendor="Hikvision") == CATEGORY_CAMERA

    def test_dell_is_computer(self) -> None:
        assert categorize_device(vendor="Dell Inc.") == CATEGORY_COMPUTER

    def test_ubiquiti_is_ap(self) -> None:
        assert categorize_device(vendor="Ubiquiti Networks Inc.") == CATEGORY_AP


class TestCategorizeByHostname:
    """Tests for hostname-based categorization."""

    def test_iphone_is_mobile(self) -> None:
        assert categorize_device(hostname="iPhone-de-Jean") == CATEGORY_MOBILE

    def test_ipad_is_tablet(self) -> None:
        assert categorize_device(hostname="iPad-Pro") == CATEGORY_TABLET

    def test_macbook_is_computer(self) -> None:
        assert categorize_device(hostname="Jeans-MacBook-Pro") == CATEGORY_COMPUTER

    def test_nas_hostname(self) -> None:
        assert categorize_device(hostname="diskstation") == CATEGORY_NAS

    def test_printer_hostname(self) -> None:
        assert categorize_device(hostname="BRW1234567890") == CATEGORY_PRINTER

    def test_esp_hostname(self) -> None:
        assert categorize_device(hostname="esp-32-sensor") == CATEGORY_IOT

    def test_desktop_hostname(self) -> None:
        assert categorize_device(hostname="DESKTOP-ABC123") == CATEGORY_COMPUTER

    def test_tv_hostname(self) -> None:
        assert categorize_device(hostname="Samsung-SmartTV") == CATEGORY_TV

    def test_echo_is_speaker(self) -> None:
        assert categorize_device(hostname="echo-dot-1234") == CATEGORY_SPEAKER

    def test_camera_hostname(self) -> None:
        assert categorize_device(hostname="doorbell-cam") == CATEGORY_CAMERA


class TestCategorizeByMac:
    """Tests for MAC OUI-based categorization."""

    def test_hyperv_mac(self) -> None:
        assert categorize_device(mac_address="00:15:5D:12:34:56") == CATEGORY_VIRTUAL

    def test_vmware_mac(self) -> None:
        assert categorize_device(mac_address="00:50:56:AB:CD:EF") == CATEGORY_VIRTUAL

    def test_virtualbox_mac(self) -> None:
        assert categorize_device(mac_address="08:00:27:12:34:56") == CATEGORY_VIRTUAL


class TestCategorizeByType:
    """Tests for device-type fallback categorization."""

    def test_wifi_ap_fallback(self) -> None:
        assert categorize_device(device_type="wifi_ap") == CATEGORY_AP

    def test_bluetooth_fallback(self) -> None:
        assert categorize_device(device_type="bluetooth") == CATEGORY_NETWORK

    def test_unknown_fallback(self) -> None:
        assert categorize_device() == CATEGORY_UNKNOWN


class TestGetCategoryLabel:
    """Tests for category label lookup."""

    def test_known_category(self) -> None:
        assert get_category_label(CATEGORY_ROUTER) == "Router/Gateway"

    def test_unknown_category(self) -> None:
        label = get_category_label("some_custom_cat")
        assert label == "Some Custom Cat"

    def test_all_categories_have_labels(self) -> None:
        categories = [
            CATEGORY_ROUTER,
            CATEGORY_AP,
            CATEGORY_NAS,
            CATEGORY_PRINTER,
            CATEGORY_COMPUTER,
            CATEGORY_MOBILE,
            CATEGORY_TABLET,
            CATEGORY_IOT,
            CATEGORY_TV,
            CATEGORY_GAMING,
            CATEGORY_CAMERA,
            CATEGORY_SPEAKER,
            CATEGORY_NETWORK,
            CATEGORY_VIRTUAL,
            CATEGORY_UNKNOWN,
        ]
        for cat in categories:
            label = get_category_label(cat)
            assert label  # Non-empty
            assert label != cat  # Different from raw constant


class TestMatchRules:
    """Tests for regex rule matching."""

    def test_match_found(self) -> None:
        rules = [(r"apple", "mobile"), (r"dell", "computer")]
        assert _match_rules("Apple Inc.", rules) == "mobile"

    def test_no_match(self) -> None:
        rules = [(r"apple", "mobile")]
        assert _match_rules("Google Inc.", rules) is None

    def test_case_insensitive(self) -> None:
        rules = [(r"SYNOLOGY", "nas")]
        assert _match_rules("synology", rules) == "nas"


class TestCategorizeDevicePriority:
    """Tests for categorization priority ordering."""

    def test_mac_takes_priority_over_vendor(self) -> None:
        """VM MAC prefix should win over vendor name."""
        result = categorize_device(
            vendor="Dell Inc.",
            mac_address="00:15:5D:12:34:56",  # Hyper-V
        )
        assert result == CATEGORY_VIRTUAL

    def test_hostname_takes_priority_over_vendor(self) -> None:
        """Hostname pattern should win over vendor name."""
        result = categorize_device(
            vendor="Apple, Inc.",
            hostname="printer-office",
        )
        assert result == CATEGORY_PRINTER
