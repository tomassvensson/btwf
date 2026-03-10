"""Tests for Bluetooth scanner module."""

from src.bluetooth_scanner import (
    BluetoothDevice,
    _is_bluetooth_adapter,
    _parse_bt_output,
)


class TestParseBtOutput:
    """Tests for Bluetooth JSON output parsing."""

    def test_empty_output(self) -> None:
        devices = _parse_bt_output("")
        assert devices == []

    def test_single_device(self) -> None:
        json_str = '[{"Name": "My Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"}]'
        devices = _parse_bt_output(json_str)
        assert len(devices) == 1
        assert devices[0].device_name == "My Phone"
        assert devices[0].mac_address == "AA:BB:CC:DD:EE:FF"
        assert devices[0].is_connected is True

    def test_single_device_as_object(self) -> None:
        """PowerShell outputs a single object (not array) when there's only one result."""
        json_str = '{"Name": "My Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"}'
        devices = _parse_bt_output(json_str)
        assert len(devices) == 1
        assert devices[0].device_name == "My Phone"

    def test_multiple_devices(self) -> None:
        json_str = """[
            {"Name": "Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"},
            {"Name": "Headphones", "MAC": "11:22:33:44:55:66", "Status": "Error", "Class": "Bluetooth"}
        ]"""
        devices = _parse_bt_output(json_str)
        assert len(devices) == 2

    def test_skips_adapter(self) -> None:
        json_str = """[
            {"Name": "Intel Wireless Bluetooth", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"},
            {"Name": "My Phone", "MAC": "11:22:33:44:55:66", "Status": "OK", "Class": "Bluetooth"}
        ]"""
        devices = _parse_bt_output(json_str)
        assert len(devices) == 1
        assert devices[0].device_name == "My Phone"

    def test_deduplicates_by_mac(self) -> None:
        json_str = """[
            {"Name": "Phone", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"},
            {"Name": "Phone (2)", "MAC": "AA:BB:CC:DD:EE:FF", "Status": "OK", "Class": "Bluetooth"}
        ]"""
        devices = _parse_bt_output(json_str)
        assert len(devices) == 1

    def test_invalid_json(self) -> None:
        devices = _parse_bt_output("not valid json")
        assert devices == []

    def test_skips_no_mac_no_name(self) -> None:
        json_str = '[{"MAC": "", "Name": "", "Status": "OK"}]'
        devices = _parse_bt_output(json_str)
        assert devices == []


class TestIsBluetoothAdapter:
    """Tests for Bluetooth adapter detection."""

    def test_intel_adapter(self) -> None:
        assert _is_bluetooth_adapter("Intel Wireless Bluetooth") is True

    def test_generic_adapter(self) -> None:
        assert _is_bluetooth_adapter("Generic Bluetooth Adapter") is True

    def test_realtek_adapter(self) -> None:
        assert _is_bluetooth_adapter("Realtek Bluetooth Adapter") is True

    def test_microsoft_enumerator(self) -> None:
        assert _is_bluetooth_adapter("Microsoft Bluetooth Enumerator") is True

    def test_regular_device(self) -> None:
        assert _is_bluetooth_adapter("My Phone") is False

    def test_headphones(self) -> None:
        assert _is_bluetooth_adapter("Sony WH-1000XM5") is False

    def test_bluetooth_keyboard(self) -> None:
        assert _is_bluetooth_adapter("Bluetooth Keyboard") is False

    def test_bluetooth_radio(self) -> None:
        assert _is_bluetooth_adapter("Bluetooth Radio") is True


class TestBluetoothDeviceDataclass:
    """Tests for BluetoothDevice dataclass."""

    def test_creation(self) -> None:
        device = BluetoothDevice(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_name="Test Device",
        )
        assert device.mac_address == "AA:BB:CC:DD:EE:FF"
        assert device.device_name == "Test Device"

    def test_vendor_auto_lookup(self) -> None:
        device = BluetoothDevice(
            mac_address="AC:BC:32:00:00:00",  # Apple OUI
        )
        assert device.vendor is not None
        assert "Apple" in device.vendor
