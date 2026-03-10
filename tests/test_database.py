"""Tests for database models and session management."""

import pytest
from sqlalchemy import create_engine

from src.database import get_session, init_database
from src.models import Base, Device, VisibilityWindow


@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


class TestDatabaseInit:
    """Tests for database initialization."""

    def test_init_creates_tables(self) -> None:
        engine = init_database("sqlite:///:memory:")
        inspector = engine.dialect.get_columns
        # Verify tables exist by querying them
        with get_session(engine) as session:
            # Should not raise
            session.query(Device).all()
            session.query(VisibilityWindow).all()

    def test_init_idempotent(self) -> None:
        """Calling init_database twice should not fail."""
        engine = init_database("sqlite:///:memory:")
        # Call again — should be fine
        Base.metadata.create_all(engine)


class TestDeviceModel:
    """Tests for the Device model."""

    def test_create_wifi_device(self, in_memory_engine) -> None:
        with get_session(in_memory_engine) as session:
            device = Device(
                mac_address="AA:BB:CC:DD:EE:FF",
                device_type="wifi_ap",
                vendor="Test Vendor",
                ssid="TestNetwork",
            )
            session.add(device)
            session.flush()

            loaded = session.query(Device).filter_by(mac_address="AA:BB:CC:DD:EE:FF").first()
            assert loaded is not None
            assert loaded.device_type == "wifi_ap"
            assert loaded.vendor == "Test Vendor"
            assert loaded.ssid == "TestNetwork"

    def test_create_bluetooth_device(self, in_memory_engine) -> None:
        with get_session(in_memory_engine) as session:
            device = Device(
                mac_address="11:22:33:44:55:66",
                device_type="bluetooth",
                device_name="My Phone",
            )
            session.add(device)
            session.flush()

            loaded = session.query(Device).filter_by(mac_address="11:22:33:44:55:66").first()
            assert loaded is not None
            assert loaded.device_type == "bluetooth"
            assert loaded.device_name == "My Phone"

    def test_mac_address_unique(self, in_memory_engine) -> None:
        from sqlalchemy.exc import IntegrityError

        with get_session(in_memory_engine) as session:
            d1 = Device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap")
            session.add(d1)
            session.flush()

        with pytest.raises(IntegrityError):
            with get_session(in_memory_engine) as session:
                d2 = Device(mac_address="AA:BB:CC:DD:EE:FF", device_type="bluetooth")
                session.add(d2)
                session.flush()

    def test_device_repr(self, in_memory_engine) -> None:
        device = Device(mac_address="AA:BB:CC:DD:EE:FF", device_type="wifi_ap", ssid="Home")
        repr_str = repr(device)
        assert "AA:BB:CC:DD:EE:FF" in repr_str
        assert "wifi_ap" in repr_str


class TestVisibilityWindowModel:
    """Tests for the VisibilityWindow model."""

    def test_create_window(self, in_memory_engine) -> None:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        with get_session(in_memory_engine) as session:
            window = VisibilityWindow(
                mac_address="AA:BB:CC:DD:EE:FF",
                first_seen=now,
                last_seen=now,
                signal_strength_dbm=-65.0,
                scan_count=1,
            )
            session.add(window)
            session.flush()

            loaded = session.query(VisibilityWindow).first()
            assert loaded is not None
            assert loaded.mac_address == "AA:BB:CC:DD:EE:FF"
            assert loaded.signal_strength_dbm == -65.0
            assert loaded.scan_count == 1

    def test_window_repr(self) -> None:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        window = VisibilityWindow(
            mac_address="AA:BB:CC:DD:EE:FF",
            first_seen=now,
            last_seen=now,
            signal_strength_dbm=-70.0,
        )
        repr_str = repr(window)
        assert "AA:BB:CC:DD:EE:FF" in repr_str
