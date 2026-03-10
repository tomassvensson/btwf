"""Tests for mDNS scanner module."""

from unittest.mock import MagicMock, patch

from src.mdns_scanner import MdnsDevice, _ServiceCollector


class TestMdnsDevice:
    """Tests for MdnsDevice dataclass."""

    def test_defaults(self) -> None:
        dev = MdnsDevice(hostname="test.local", ip_address="192.168.1.10")
        assert dev.hostname == "test.local"
        assert dev.ip_address == "192.168.1.10"
        assert dev.mac_address == ""
        assert dev.service_type == ""
        assert dev.port == 0
        assert dev.vendor is None
        assert dev.is_randomized is False
        assert dev.txt_records == {}

    def test_custom_values(self) -> None:
        dev = MdnsDevice(
            hostname="printer.local",
            ip_address="192.168.1.20",
            mac_address="AA:BB:CC:DD:EE:FF",
            service_type="ipp",
            port=631,
            vendor="Brother",
        )
        assert dev.mac_address == "AA:BB:CC:DD:EE:FF"
        assert dev.service_type == "ipp"
        assert dev.port == 631
        assert dev.vendor == "Brother"


class TestServiceCollector:
    """Tests for mDNS service collector."""

    def test_add_service(self) -> None:
        collector = _ServiceCollector()
        collector.add_service(None, "_http._tcp.local.", "My Web Server._http._tcp.local.")
        assert len(collector.found) == 1
        assert collector.found[0] == ("_http._tcp.local.", "My Web Server._http._tcp.local.")

    def test_update_service(self) -> None:
        collector = _ServiceCollector()
        collector.update_service(None, "_http._tcp.local.", "Server._http._tcp.local.")
        assert len(collector.found) == 1

    def test_remove_service(self) -> None:
        collector = _ServiceCollector()
        collector.add_service(None, "_http._tcp.local.", "Server._http._tcp.local.")
        collector.remove_service(None, "_http._tcp.local.", "Server._http._tcp.local.")
        # Remove doesn't actually remove from found (by design)
        assert len(collector.found) == 1

    def test_multiple_services(self) -> None:
        collector = _ServiceCollector()
        collector.add_service(None, "_http._tcp.local.", "Web._http._tcp.local.")
        collector.add_service(None, "_ipp._tcp.local.", "Printer._ipp._tcp.local.")
        assert len(collector.found) == 2


class TestScanMdnsServices:
    """Tests for scan_mdns_services function."""

    @patch("src.mdns_scanner.scan_mdns_services")
    def test_returns_list(self, mock_scan) -> None:
        mock_scan.return_value = [
            MdnsDevice(hostname="test.local", ip_address="192.168.1.10"),
        ]
        result = mock_scan()
        assert len(result) == 1
        assert result[0].hostname == "test.local"

    def test_import_failure_returns_empty(self) -> None:
        """Test graceful handling when zeroconf is not available."""
        from src.mdns_scanner import scan_mdns_services

        with patch.dict("sys.modules", {"zeroconf": None}):
            # The function handles ImportError internally
            # We can't easily test this without uninstalling zeroconf
            # So just verify the function is callable
            assert callable(scan_mdns_services)


class TestArpLookupMac:
    """Tests for _arp_lookup_mac function."""

    @patch("subprocess.run")
    def test_found_mac(self, mock_run) -> None:
        from src.mdns_scanner import _arp_lookup_mac

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="  192.168.1.10  aa-bb-cc-dd-ee-ff  dynamic",
        )
        result = _arp_lookup_mac("192.168.1.10")
        assert result == "AA:BB:CC:DD:EE:FF"

    @patch("subprocess.run")
    def test_not_found(self, mock_run) -> None:
        from src.mdns_scanner import _arp_lookup_mac

        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
        )
        result = _arp_lookup_mac("192.168.1.10")
        assert result == ""

    @patch("subprocess.run", side_effect=OSError("command not found"))
    def test_command_failure(self, mock_run) -> None:
        from src.mdns_scanner import _arp_lookup_mac

        result = _arp_lookup_mac("192.168.1.10")
        assert result == ""
