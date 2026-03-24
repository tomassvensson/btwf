"""Tests for device fingerprinting."""

import pytest

from src.fingerprint import (
    DeviceFingerprint,
    _parse_os_string,
    fingerprint_from_hostname,
    fingerprint_from_mdns_txt,
    fingerprint_from_ssdp_server,
)


class TestDeviceFingerprint:
    """Tests for DeviceFingerprint dataclass."""

    def test_default_values(self) -> None:
        fp = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF")
        assert fp.mac_address == "AA:BB:CC:DD:EE:FF"
        assert fp.os_family == ""
        assert fp.os_version == ""
        assert fp.device_model == ""
        assert fp.manufacturer == ""
        assert fp.services == []
        assert fp.confidence == pytest.approx(0.0)

    def test_merge_fills_empty_fields(self) -> None:
        fp1 = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF", os_family="macOS")
        fp2 = DeviceFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            os_version="14.2",
            manufacturer="Apple",
            device_model="MacBook Pro",
            services=["http"],
            confidence=0.8,
        )
        fp1.merge(fp2)
        assert fp1.os_family == "macOS"  # not overwritten
        assert fp1.os_version == "14.2"
        assert fp1.manufacturer == "Apple"
        assert fp1.device_model == "MacBook Pro"
        assert "http" in fp1.services
        assert fp1.confidence == pytest.approx(0.8)

    def test_merge_does_not_overwrite(self) -> None:
        fp1 = DeviceFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            os_family="macOS",
            manufacturer="Apple",
        )
        fp2 = DeviceFingerprint(
            mac_address="AA:BB:CC:DD:EE:FF",
            os_family="Linux",
            manufacturer="Dell",
        )
        fp1.merge(fp2)
        assert fp1.os_family == "macOS"
        assert fp1.manufacturer == "Apple"

    def test_merge_deduplicates_services(self) -> None:
        fp1 = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF", services=["http"])
        fp2 = DeviceFingerprint(mac_address="AA:BB:CC:DD:EE:FF", services=["http", "ssh"])
        fp1.merge(fp2)
        assert fp1.services == ["http", "ssh"]


class TestFingerprintFromMdnsTxt:
    """Tests for mDNS TXT record fingerprinting."""

    def test_model_descriptor(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {"md": "Synology DS920+"})
        assert fp.device_model == "Synology DS920+"
        assert fp.confidence >= 0.7

    def test_apple_model(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {"am": "MacBookPro18,1"})
        assert fp.device_model == "MacBookPro18,1"
        assert fp.manufacturer == "Apple"
        assert fp.confidence >= 0.8

    def test_os_info(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {"os": "macOS 14.2"})
        assert fp.os_family == "macOS"
        assert fp.os_version == "14.2"

    def test_friendly_name(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {"fn": "Living Room Speaker"})
        assert fp.device_model == "Living Room Speaker"

    def test_service_type_recorded(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {}, service_type="_http._tcp")
        assert "_http._tcp" in fp.services

    def test_empty_records(self) -> None:
        fp = fingerprint_from_mdns_txt("AA:BB:CC:DD:EE:FF", {})
        assert fp.device_model == ""
        assert fp.confidence == pytest.approx(0.0)


class TestFingerprintFromSsdpServer:
    """Tests for SSDP server string fingerprinting."""

    def test_linux_server(self) -> None:
        fp = fingerprint_from_ssdp_server("AA:BB:CC:DD:EE:FF", "Linux/4.14.0 UPnP/1.0 Synology/DSM")
        assert fp.os_family == "Linux"
        assert fp.os_version == "4.14.0"
        assert fp.manufacturer == "Synology"

    def test_windows_server(self) -> None:
        fp = fingerprint_from_ssdp_server("AA:BB:CC:DD:EE:FF", "Windows/10.0 UPnP/1.0")
        assert fp.os_family == "Windows"
        assert fp.os_version == "10.0"

    def test_empty_server_string(self) -> None:
        fp = fingerprint_from_ssdp_server("AA:BB:CC:DD:EE:FF", "")
        assert fp.os_family == ""
        assert fp.confidence == pytest.approx(0.0)

    def test_product_only(self) -> None:
        fp = fingerprint_from_ssdp_server("AA:BB:CC:DD:EE:FF", "SomeProduct/2.0")
        assert fp.manufacturer == "SomeProduct"
        assert fp.confidence >= 0.4


class TestFingerprintFromHostname:
    """Tests for hostname-based fingerprinting."""

    def test_iphone(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "iPhone-de-Jean")
        assert fp.manufacturer == "Apple"
        assert fp.device_model == "iPhone"
        assert fp.os_family == "iOS"

    def test_ipad(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "iPad-Pro")
        assert fp.manufacturer == "Apple"
        assert fp.device_model == "iPad"
        assert fp.os_family == "iOS"

    def test_macbook(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "Jeans-MacBook-Pro")
        assert fp.manufacturer == "Apple"
        assert fp.device_model == "MacBook"
        assert fp.os_family == "macOS"

    def test_galaxy(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "Galaxy-S23")
        assert fp.manufacturer == "Samsung"
        assert "Galaxy" in fp.device_model
        assert fp.os_family == "Android"

    def test_windows_desktop(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "DESKTOP-ABC123")
        assert fp.os_family == "Windows"

    def test_android_hostname(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "android-abc123")
        assert fp.os_family == "Android"

    def test_synology(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "DiskStation")
        assert fp.manufacturer == "Synology"
        assert fp.os_family == "DSM"

    def test_empty_hostname(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "")
        assert fp.os_family == ""
        assert fp.confidence == pytest.approx(0.0)

    def test_generic_hostname(self) -> None:
        fp = fingerprint_from_hostname("AA:BB:CC:DD:EE:FF", "just-a-hostname")
        assert fp.confidence == pytest.approx(0.0)


class TestParseOsString:
    """Tests for OS string parsing."""

    def test_macos(self) -> None:
        family, version = _parse_os_string("macOS 14.2")
        assert family == "macOS"
        assert version == "14.2"

    def test_linux(self) -> None:
        family, version = _parse_os_string("Linux 5.15.0")
        assert family == "Linux"
        assert version == "5.15.0"

    def test_no_version(self) -> None:
        family, version = _parse_os_string("FreeBSD")
        assert family == "FreeBSD"
        assert version == ""

    def test_empty_string(self) -> None:
        family, version = _parse_os_string("")
        assert family == ""
        assert version == ""
