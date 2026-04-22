"""Tests for network discovery (ARP scanning) module."""

import pytest

from src.network_discovery import NetworkDevice, _parse_arp_output


class TestParseArpOutput:
    """Tests for ARP output parsing."""

    SAMPLE_OUTPUT = """
Interface: 192.168.1.1 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.2           aa-bb-cc-dd-ee-f1     dynamic
  192.168.1.3           10-22-33-44-55-66     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static

Interface: 192.168.2.1 --- 0x8
  Internet Address      Physical Address      Type
  192.168.2.5           aa-bb-cc-dd-ee-f2     dynamic
"""

    @pytest.mark.timeout(30)
    def test_parses_dynamic_entries(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        # Should find 3 unicast devices (broadcast ff-ff and multicast 01-00-5e excluded)
        assert len(devices) == 3

    @pytest.mark.timeout(30)
    def test_skips_broadcast(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        macs = [d.mac_address for d in devices]
        assert "FF:FF:FF:FF:FF:FF" not in macs

    @pytest.mark.timeout(30)
    def test_skips_multicast(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        macs = [d.mac_address for d in devices]
        # 01:00:5E is multicast
        assert not any(m.startswith("01:") for m in macs)

    @pytest.mark.timeout(30)
    def test_normalizes_mac(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        assert any(d.mac_address == "AA:BB:CC:DD:EE:F1" for d in devices)

    @pytest.mark.timeout(30)
    def test_captures_ip(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        device = next(d for d in devices if d.mac_address == "AA:BB:CC:DD:EE:F1")
        assert device.ip_address == "192.168.1.2"

    @pytest.mark.timeout(30)
    def test_captures_interface(self) -> None:
        devices = _parse_arp_output(self.SAMPLE_OUTPUT)
        d1 = next(d for d in devices if d.mac_address == "AA:BB:CC:DD:EE:F1")
        assert d1.interface == "192.168.1.1"

    @pytest.mark.timeout(30)
    def test_deduplicates_by_mac(self) -> None:
        dup_output = """
Interface: 192.168.1.1 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.2           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.3           aa-bb-cc-dd-ee-ff     dynamic
"""
        devices = _parse_arp_output(dup_output)
        assert len(devices) == 1

    @pytest.mark.timeout(30)
    def test_empty_output(self) -> None:
        devices = _parse_arp_output("")
        assert devices == []


class TestNetworkDeviceDataclass:
    """Tests for NetworkDevice dataclass."""

    @pytest.mark.timeout(30)
    def test_creation(self) -> None:
        device = NetworkDevice(
            ip_address="192.168.1.2",
            mac_address="AA:BB:CC:DD:EE:FF",
        )
        assert device.ip_address == "192.168.1.2"
        assert device.arp_type == "dynamic"

    @pytest.mark.timeout(30)
    def test_vendor_auto_lookup(self) -> None:
        device = NetworkDevice(
            ip_address="192.168.1.2",
            mac_address="AC:BC:32:00:00:00",  # Apple OUI
        )
        assert device.vendor is not None
        assert "Apple" in device.vendor
