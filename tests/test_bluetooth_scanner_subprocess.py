"""Tests for Bluetooth scanner subprocess calls (mocked)."""

from unittest.mock import MagicMock, patch

import pytest

from src.bluetooth_scanner import scan_bluetooth_devices


class TestScanBluetoothDevices:
    """Tests for scan_bluetooth_devices with mocked subprocess."""

    @patch("src.bluetooth_scanner.subprocess.run")
    @pytest.mark.timeout(30)
    def test_successful_scan(self, mock_run) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='[{"Name": "Test Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"}]',
            stderr="",
        )
        devices = scan_bluetooth_devices()
        assert len(devices) == 1
        assert devices[0].device_name == "Test Phone"

    @patch("src.bluetooth_scanner.subprocess.run")
    @pytest.mark.timeout(30)
    def test_empty_scan(self, mock_run) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        devices = scan_bluetooth_devices()
        assert devices == []

    @patch("src.bluetooth_scanner.subprocess.run")
    @pytest.mark.timeout(30)
    def test_powershell_not_found(self, mock_run) -> None:
        mock_run.side_effect = FileNotFoundError()
        with pytest.raises(RuntimeError, match="PowerShell"):
            scan_bluetooth_devices()

    @patch("src.bluetooth_scanner.subprocess.run")
    @pytest.mark.timeout(30)
    def test_timeout(self, mock_run) -> None:
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="powershell", timeout=30)
        with pytest.raises(RuntimeError, match="timed out"):
            scan_bluetooth_devices()

    @patch("src.bluetooth_scanner.subprocess.run")
    @pytest.mark.timeout(30)
    def test_scan_with_warnings(self, mock_run) -> None:
        """Scan continues even if PowerShell emits warnings."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='[{"Name": "Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"}]',
            stderr="Some warning message",
        )
        devices = scan_bluetooth_devices()
        assert len(devices) == 1
