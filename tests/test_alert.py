"""Tests for alert management system."""

from src.alert import AlertManager
from src.config import AlertConfig


class TestAlertManager:
    """Tests for AlertManager."""

    def test_alert_disabled(self) -> None:
        config = AlertConfig(enabled=False)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
        )
        assert mgr.alert_count == 0

    def test_alert_enabled_increments_count(self) -> None:
        config = AlertConfig(enabled=True, log_new_devices=False)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
            vendor="TestVendor",
            device_name="TestDevice",
        )
        assert mgr.alert_count == 1

    def test_alert_whitelisted_device(self) -> None:
        config = AlertConfig(enabled=True, log_new_devices=True)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="network",
            vendor="Known",
            device_name="MyServer",
            is_whitelisted=True,
        )
        assert mgr.alert_count == 1

    def test_alert_unknown_device(self) -> None:
        config = AlertConfig(enabled=True, log_new_devices=True)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="bluetooth",
            is_whitelisted=False,
        )
        assert mgr.alert_count == 1

    def test_multiple_alerts(self) -> None:
        config = AlertConfig(enabled=True)
        mgr = AlertManager(config)
        for i in range(5):
            mgr.on_new_device(
                mac_address=f"AA:BB:CC:DD:EE:{i:02X}",
                device_type="wifi_ap",
            )
        assert mgr.alert_count == 5

    def test_alert_with_log_file(self, tmp_path) -> None:
        log_file = str(tmp_path / "alerts.log")
        config = AlertConfig(enabled=True, log_file=log_file, log_new_devices=True)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="network",
            vendor="Test",
            device_name="TestDev",
        )
        assert mgr.alert_count == 1

    def test_alert_log_file_failure(self, tmp_path) -> None:
        """Test that AlertManager handles log file creation failure gracefully."""
        config = AlertConfig(enabled=True, log_file="/nonexistent/dir/alerts.log")
        # Should not raise — just logs a warning
        mgr = AlertManager(config)
        assert mgr.alert_count == 0

    def test_no_vendor_no_name(self) -> None:
        config = AlertConfig(enabled=True, log_new_devices=True)
        mgr = AlertManager(config)
        mgr.on_new_device(
            mac_address="AA:BB:CC:DD:EE:FF",
            device_type="wifi_ap",
        )
        assert mgr.alert_count == 1
