"""Tests for OUI/vendor lookup module."""

import pytest

from src.oui_lookup import (
    get_oui_prefix,
    is_randomized_mac,
    lookup_vendor,
    normalize_mac,
)


class TestNormalizeMac:
    """Tests for MAC address normalization."""

    def test_colon_separated(self) -> None:
        assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_hyphen_separated(self) -> None:
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"

    def test_dot_separated(self) -> None:
        assert normalize_mac("aabb.ccdd.eeff") == "AA:BB:CC:DD:EE:FF"

    def test_no_separator(self) -> None:
        assert normalize_mac("AABBCCDDEEFF") == "AA:BB:CC:DD:EE:FF"

    def test_with_whitespace(self) -> None:
        assert normalize_mac("  aa:bb:cc:dd:ee:ff  ") == "AA:BB:CC:DD:EE:FF"

    def test_mixed_case(self) -> None:
        assert normalize_mac("Aa:Bb:Cc:Dd:Ee:Ff") == "AA:BB:CC:DD:EE:FF"

    def test_invalid_too_short(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("aa:bb:cc")

    def test_invalid_too_long(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("aa:bb:cc:dd:ee:ff:00")

    def test_invalid_characters(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("gg:hh:ii:jj:kk:ll")

    def test_empty_string(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC"):
            normalize_mac("")


class TestGetOuiPrefix:
    """Tests for OUI prefix extraction."""

    def test_standard_mac(self) -> None:
        assert get_oui_prefix("AA:BB:CC:DD:EE:FF") == "AA:BB:CC"

    def test_lowercase_mac(self) -> None:
        assert get_oui_prefix("aa:bb:cc:dd:ee:ff") == "AA:BB:CC"

    def test_hyphen_separated(self) -> None:
        assert get_oui_prefix("14-CC-20-01-02-03") == "14:CC:20"


class TestLookupVendor:
    """Tests for vendor lookup."""

    def test_known_apple_mac(self) -> None:
        vendor = lookup_vendor("AC:BC:32:00:00:00")
        assert vendor is not None
        assert "Apple" in vendor

    def test_known_samsung_mac(self) -> None:
        vendor = lookup_vendor("00:07:AB:00:00:00")
        assert vendor is not None
        assert "Samsung" in vendor

    def test_known_tp_link_mac(self) -> None:
        vendor = lookup_vendor("14:CC:20:00:00:00")
        assert vendor is not None
        # Could be "TP-Link" from full DB or builtin
        assert "TP" in vendor or "tp" in vendor.lower()

    def test_known_intel_mac(self) -> None:
        vendor = lookup_vendor("00:13:E8:00:00:00")
        assert vendor is not None
        assert "Intel" in vendor

    def test_invalid_mac_returns_none(self) -> None:
        assert lookup_vendor("invalid") is None

    def test_unknown_mac_returns_none_or_vendor(self) -> None:
        """Unknown MACs should return None from builtin, may return value from full DB."""
        result = lookup_vendor("00:00:00:00:00:01")
        # This may return something from the full database or None from builtin
        # Either outcome is acceptable
        assert result is None or isinstance(result, str)


class TestIsRandomizedMac:
    """Tests for randomized/locally administered MAC detection."""

    def test_globally_unique_mac(self) -> None:
        # First byte 0x00 — bit 1 is 0 → globally unique
        assert is_randomized_mac("00:11:22:33:44:55") is False

    def test_locally_administered_mac(self) -> None:
        # First byte 0x02 — bit 1 is 1 → locally administered
        assert is_randomized_mac("02:11:22:33:44:55") is True

    def test_another_locally_administered(self) -> None:
        # First byte 0x06 — bit 1 is 1 → locally administered
        assert is_randomized_mac("06:11:22:33:44:55") is True

    def test_common_vendor_mac_not_random(self) -> None:
        # Apple MAC — should not be randomized
        assert is_randomized_mac("AC:BC:32:00:00:00") is False

    def test_invalid_mac_returns_false(self) -> None:
        assert is_randomized_mac("invalid") is False
