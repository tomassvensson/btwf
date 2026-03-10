"""Tests for main module — display and scan orchestration."""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine

from src.config import AppConfig
from src.database import get_session
from src.main import (
    _best_name,
    _display_results,
    _format_signal,
    _format_time,
    _friendly_vendor,
    _shorten_vendor_name,
    run_scan,
)
from src.models import Base, Device, VisibilityWindow


@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


class TestFormatSignal:
    """Tests for signal strength formatting."""

    def test_none(self) -> None:
        assert _format_signal(None) == "N/A"

    def test_excellent(self) -> None:
        result = _format_signal(-45.0)
        assert "Excellent" in result
        assert "-45" in result

    def test_good(self) -> None:
        result = _format_signal(-55.0)
        assert "Good" in result

    def test_fair(self) -> None:
        result = _format_signal(-65.0)
        assert "Fair" in result

    def test_weak(self) -> None:
        result = _format_signal(-75.0)
        assert "Weak" in result

    def test_very_weak(self) -> None:
        result = _format_signal(-90.0)
        assert "Very Weak" in result


class TestFormatTime:
    """Tests for time formatting."""

    def test_none(self) -> None:
        assert _format_time(None) == "N/A"

    def test_datetime(self) -> None:
        dt = datetime(2026, 3, 9, 14, 30, 0)
        result = _format_time(dt)
        assert "2026-03-09" in result
        assert "14:30:00" in result


class TestShortenVendorName:
    """Tests for automatic vendor name shortening."""

    def test_strips_inc(self) -> None:
        assert _shorten_vendor_name("Espressif Inc.") == "Espressif"

    def test_strips_corporation(self) -> None:
        assert _shorten_vendor_name("Microsoft Corporation") == "Microsoft"

    def test_strips_co_ltd(self) -> None:
        assert _shorten_vendor_name("Samsung Electronics Co.,Ltd") == "Samsung"

    def test_strips_gmbh(self) -> None:
        assert _shorten_vendor_name("BSH Hausgeräte GmbH") == "BSH Hausgeräte"

    def test_strips_technologies(self) -> None:
        assert _shorten_vendor_name("TP-LINK TECHNOLOGIES CO.,LTD.") == "TP-LINK"

    def test_strips_parenthetical(self) -> None:
        result = _shorten_vendor_name("LG Electronics (Mobile Communications)")
        assert result == "LG"

    def test_preserves_simple_name(self) -> None:
        assert _shorten_vendor_name("Apple") == "Apple"

    def test_preserves_short_name(self) -> None:
        assert _shorten_vendor_name("Dell") == "Dell"


class TestFriendlyVendor:
    """Tests for vendor name display."""

    def test_known_vendor(self) -> None:
        result = _friendly_vendor("Google, Inc.", "AA:BB:CC:DD:EE:FF")
        assert result == "Google"

    def test_randomized_mac_no_vendor(self) -> None:
        # Locally administered (randomized) MAC: bit 1 of first byte set
        result = _friendly_vendor(None, "FA:BB:CC:DD:EE:FF")
        assert "Randomized" in result

    def test_no_vendor_no_randomized(self) -> None:
        result = _friendly_vendor(None, "00:BB:CC:DD:EE:FF")
        assert "Unknown" in result


class TestBestName:
    """Tests for best device name selection."""

    def test_device_name_preferred(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            device_name="MyRouter",
            ssid="Home",
        )
        assert _best_name(device) == "MyRouter"

    def test_hostname_when_no_name(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="network",
            hostname="my-server",
        )
        assert _best_name(device) == "my-server"

    def test_ssid_when_no_name_or_hostname(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            ssid="Home",
        )
        assert _best_name(device) == "Home"

    def test_vendor_when_no_name_or_ssid(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            vendor="TP-Link",
        )
        assert _best_name(device) == "TP-Link device"

    def test_mac_as_fallback(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
        )
        assert _best_name(device) == "AA:BB:CC:DD:EE:FF"

    def test_hidden_ssid_uses_vendor(self) -> None:
        device = Device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            ssid="<Hidden>",
            vendor="Netgear",
        )
        assert _best_name(device) == "Netgear device"


class TestDisplayResults:
    """Tests for result display."""

    def test_no_devices(self, in_memory_engine, capsys) -> None:
        with get_session(in_memory_engine) as session:
            _display_results(session)
        captured = capsys.readouterr()
        assert "No devices found" in captured.out

    def test_with_devices(self, in_memory_engine, capsys) -> None:
        now = datetime.now(timezone.utc)
        with get_session(in_memory_engine) as session:
            device = Device(
                mac_address="AA:BB:CC:DD:EE:FF",
                device_type="wifi_ap",
                ssid="TestNet",
                vendor="TestVendor",
                authentication="WPA2",
                encryption="CCMP",
                radio_type="802.11ac",
                channel=36,
            )
            session.add(device)
            session.flush()

            window = VisibilityWindow(
                mac_address="AA:BB:CC:DD:EE:FF",
                first_seen=now,
                last_seen=now,
                signal_strength_dbm=-65.0,
                scan_count=1,
            )
            session.add(window)
            session.flush()

            _display_results(session)

        captured = capsys.readouterr()
        assert "DISCOVERED DEVICES" in captured.out
        assert "TestNet" in captured.out
        assert "TestVendor" in captured.out
        assert "Total devices:" in captured.out


class TestRunScan:
    """Integration-level tests for the full scan cycle."""

    @patch("src.main.scan_arp_table")
    @patch("src.main.scan_bluetooth_devices")
    @patch("src.main.scan_wifi_networks")
    @patch("src.main.init_database")
    def test_full_scan_with_mocked_scanners(
        self,
        mock_init_db,
        mock_wifi_scan,
        mock_bt_scan,
        mock_arp_scan,
    ) -> None:
        """Test full scan cycle with mocked external dependencies."""
        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        mock_init_db.return_value = engine

        from src.wifi_scanner import WifiNetwork

        mock_wifi_scan.return_value = [
            WifiNetwork(
                ssid="MockNet",
                bssid="AA:BB:CC:DD:EE:FF",
                network_type="Infrastructure",
                authentication="WPA2-Personal",
                encryption="CCMP",
                signal_percent=80,
                signal_dbm=-60.0,
                radio_type="802.11ac",
                channel=36,
            )
        ]

        from src.bluetooth_scanner import BluetoothDevice

        mock_bt_scan.return_value = [BluetoothDevice(mac_address="11:22:33:44:55:66", device_name="MockPhone")]

        from src.network_discovery import NetworkDevice

        mock_arp_scan.return_value = [
            NetworkDevice(
                ip_address="192.168.1.100",
                mac_address="AA:00:CC:DD:EE:FF",
                hostname="my-laptop",
            )
        ]

        config = AppConfig()
        config.scan.mdns_enabled = False
        config.scan.ssdp_enabled = False
        config.scan.netbios_enabled = False
        run_scan(config)

        with get_session(engine) as session:
            devices = session.query(Device).all()
            assert len(devices) == 3

    @patch("src.main.scan_arp_table")
    @patch("src.main.scan_bluetooth_devices")
    @patch("src.main.scan_wifi_networks")
    @patch("src.main.init_database")
    def test_scan_handles_scanner_errors(
        self,
        mock_init_db,
        mock_wifi_scan,
        mock_bt_scan,
        mock_arp_scan,
    ) -> None:
        """Test that scan continues even if individual scanners fail."""
        engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(engine)
        mock_init_db.return_value = engine

        mock_wifi_scan.side_effect = RuntimeError("WiFi not available")
        mock_bt_scan.side_effect = RuntimeError("BT not available")
        mock_arp_scan.return_value = []

        config = AppConfig()
        config.scan.mdns_enabled = False
        config.scan.ssdp_enabled = False
        config.scan.netbios_enabled = False
        run_scan(config)
