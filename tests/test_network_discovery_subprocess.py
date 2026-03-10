"""Tests for network discovery subprocess calls (mocked)."""

from unittest.mock import MagicMock, patch

from src.network_discovery import _resolve_hostname, scan_arp_table


class TestScanArpTable:
    """Tests for scan_arp_table with mocked subprocess."""

    @patch("src.network_discovery._resolve_hostname")
    @patch("src.network_discovery.subprocess.run")
    def test_successful_scan(self, mock_run, mock_resolve) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="""
Interface: 192.168.1.1 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.2           aa-bb-cc-dd-ee-f0     dynamic
""",
            stderr="",
        )
        mock_resolve.return_value = "my-laptop.local"

        devices = scan_arp_table()
        assert len(devices) == 1
        assert devices[0].hostname == "my-laptop.local"

    @patch("src.network_discovery.subprocess.run")
    def test_command_not_found(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError()
        devices = scan_arp_table()
        assert devices == []

    @patch("src.network_discovery.subprocess.run")
    def test_timeout(self, mock_run) -> None:
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="arp", timeout=15)
        devices = scan_arp_table()
        assert devices == []

    @patch("src.network_discovery.subprocess.run")
    def test_command_failure(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")
        devices = scan_arp_table()
        assert devices == []


class TestResolveHostname:
    """Tests for hostname resolution."""

    @patch("src.network_discovery.socket.gethostbyaddr")
    def test_successful_resolve(self, mock_resolve) -> None:
        mock_resolve.return_value = ("my-laptop.local", [], ["192.168.1.2"])
        hostname = _resolve_hostname("192.168.1.2")
        assert hostname == "my-laptop.local"

    @patch("src.network_discovery.socket.gethostbyaddr")
    def test_resolve_failure(self, mock_resolve) -> None:
        import socket

        mock_resolve.side_effect = socket.herror("Not found")
        hostname = _resolve_hostname("192.168.1.2")
        assert hostname is None

    @patch("src.network_discovery.socket.gethostbyaddr")
    def test_resolve_returns_ip(self, mock_resolve) -> None:
        """If hostname equals IP, return None."""
        mock_resolve.return_value = ("192.168.1.2", [], ["192.168.1.2"])
        hostname = _resolve_hostname("192.168.1.2")
        assert hostname is None
