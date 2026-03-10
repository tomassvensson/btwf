"""Application configuration management.

Loads configuration from a YAML file (config.yaml) with environment variable
overrides. Provides sensible defaults for all settings.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = "config.yaml"


@dataclass
class ScanConfig:
    """Scan timing and behavior settings."""

    continuous: bool = False
    interval_seconds: int = 60
    gap_seconds: int = 300
    wifi_enabled: bool = True
    bluetooth_enabled: bool = True
    ble_enabled: bool = True
    arp_enabled: bool = True
    mdns_enabled: bool = True
    ssdp_enabled: bool = True
    netbios_enabled: bool = True
    snmp_enabled: bool = False
    monitor_mode_enabled: bool = False


@dataclass
class ArpConfig:
    """ARP hostname resolution settings."""

    resolve_hostnames: bool = True
    max_concurrent: int = 10
    timeout_seconds: float = 2.0
    min_delay_seconds: float = 0.05
    max_delay_seconds: float = 0.2
    jitter: bool = True


@dataclass
class SnmpConfig:
    """SNMP discovery settings."""

    community: str = "public"
    version: int = 2
    port: int = 161
    timeout_seconds: float = 2.0
    target_hosts: list[str] = field(default_factory=list)


@dataclass
class DatabaseConfig:
    """Database configuration."""

    url: str = "sqlite:///btwifi.db"


@dataclass
class AlertConfig:
    """Alert/notification settings."""

    enabled: bool = True
    log_new_devices: bool = True
    log_file: str | None = None
    sound_enabled: bool = False


@dataclass
class WhitelistEntry:
    """A known/trusted device."""

    mac_address: str
    name: str = ""
    category: str = ""
    trusted: bool = True


@dataclass
class OuiConfig:
    """OUI database update settings."""

    auto_update: bool = True
    update_interval_hours: int = 168  # 1 week
    cache_file: str = "src/data/oui_cache.txt"


@dataclass
class MonitorModeConfig:
    """Monitor mode (scapy) settings."""

    interface: str = "wlan0mon"
    use_docker: bool = True
    docker_image: str = "btwifi-monitor:latest"
    channel_hop: bool = True
    hop_interval_seconds: float = 0.5
    capture_duration_seconds: int = 30


@dataclass
class AppConfig:
    """Root application configuration."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    arp: ArpConfig = field(default_factory=ArpConfig)
    snmp: SnmpConfig = field(default_factory=SnmpConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    alert: AlertConfig = field(default_factory=AlertConfig)
    whitelist: list[WhitelistEntry] = field(default_factory=list)
    oui: OuiConfig = field(default_factory=OuiConfig)
    monitor_mode: MonitorModeConfig = field(default_factory=MonitorModeConfig)


def load_config(config_path: str | None = None) -> AppConfig:
    """Load configuration from YAML file with env var overrides.

    Args:
        config_path: Path to YAML config file. Defaults to config.yaml.

    Returns:
        Populated AppConfig instance.
    """
    path = config_path or os.environ.get("BTWIFI_CONFIG", _DEFAULT_CONFIG_PATH)
    config = AppConfig()

    if Path(path).exists():
        try:
            import yaml  # noqa: F811
        except ImportError:
            logger.warning("PyYAML not installed. Using default configuration. Install with: pip install pyyaml")
            return _apply_env_overrides(config)

        try:
            with open(path, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            config = _parse_raw_config(raw)
            logger.info("Configuration loaded from %s", path)
        except Exception:
            logger.exception("Failed to load config from %s, using defaults.", path)
    else:
        logger.debug("No config file at %s, using defaults.", path)

    return _apply_env_overrides(config)


def _parse_raw_config(raw: dict) -> AppConfig:
    """Parse a raw dictionary into an AppConfig.

    Args:
        raw: Dictionary from YAML parsing.

    Returns:
        Populated AppConfig.
    """
    config = AppConfig()

    if "scan" in raw:
        s = raw["scan"]
        config.scan = ScanConfig(
            continuous=s.get("continuous", config.scan.continuous),
            interval_seconds=s.get("interval_seconds", config.scan.interval_seconds),
            gap_seconds=s.get("gap_seconds", config.scan.gap_seconds),
            wifi_enabled=s.get("wifi_enabled", config.scan.wifi_enabled),
            bluetooth_enabled=s.get("bluetooth_enabled", config.scan.bluetooth_enabled),
            ble_enabled=s.get("ble_enabled", config.scan.ble_enabled),
            arp_enabled=s.get("arp_enabled", config.scan.arp_enabled),
            mdns_enabled=s.get("mdns_enabled", config.scan.mdns_enabled),
            ssdp_enabled=s.get("ssdp_enabled", config.scan.ssdp_enabled),
            netbios_enabled=s.get("netbios_enabled", config.scan.netbios_enabled),
            snmp_enabled=s.get("snmp_enabled", config.scan.snmp_enabled),
            monitor_mode_enabled=s.get("monitor_mode_enabled", config.scan.monitor_mode_enabled),
        )

    if "arp" in raw:
        a = raw["arp"]
        config.arp = ArpConfig(
            resolve_hostnames=a.get("resolve_hostnames", config.arp.resolve_hostnames),
            max_concurrent=a.get("max_concurrent", config.arp.max_concurrent),
            timeout_seconds=a.get("timeout_seconds", config.arp.timeout_seconds),
            min_delay_seconds=a.get("min_delay_seconds", config.arp.min_delay_seconds),
            max_delay_seconds=a.get("max_delay_seconds", config.arp.max_delay_seconds),
            jitter=a.get("jitter", config.arp.jitter),
        )

    if "snmp" in raw:
        sn = raw["snmp"]
        config.snmp = SnmpConfig(
            community=sn.get("community", config.snmp.community),
            version=sn.get("version", config.snmp.version),
            port=sn.get("port", config.snmp.port),
            timeout_seconds=sn.get("timeout_seconds", config.snmp.timeout_seconds),
            target_hosts=sn.get("target_hosts", config.snmp.target_hosts),
        )

    if "database" in raw:
        config.database = DatabaseConfig(
            url=raw["database"].get("url", config.database.url),
        )

    if "alert" in raw:
        al = raw["alert"]
        config.alert = AlertConfig(
            enabled=al.get("enabled", config.alert.enabled),
            log_new_devices=al.get("log_new_devices", config.alert.log_new_devices),
            log_file=al.get("log_file", config.alert.log_file),
            sound_enabled=al.get("sound_enabled", config.alert.sound_enabled),
        )

    if "whitelist" in raw:
        config.whitelist = [
            WhitelistEntry(
                mac_address=entry.get("mac_address", ""),
                name=entry.get("name", ""),
                category=entry.get("category", ""),
                trusted=entry.get("trusted", True),
            )
            for entry in raw["whitelist"]
            if isinstance(entry, dict) and entry.get("mac_address")
        ]

    if "oui" in raw:
        o = raw["oui"]
        config.oui = OuiConfig(
            auto_update=o.get("auto_update", config.oui.auto_update),
            update_interval_hours=o.get("update_interval_hours", config.oui.update_interval_hours),
            cache_file=o.get("cache_file", config.oui.cache_file),
        )

    if "monitor_mode" in raw:
        mm = raw["monitor_mode"]
        config.monitor_mode = MonitorModeConfig(
            interface=mm.get("interface", config.monitor_mode.interface),
            use_docker=mm.get("use_docker", config.monitor_mode.use_docker),
            docker_image=mm.get("docker_image", config.monitor_mode.docker_image),
            channel_hop=mm.get("channel_hop", config.monitor_mode.channel_hop),
            hop_interval_seconds=mm.get("hop_interval_seconds", config.monitor_mode.hop_interval_seconds),
            capture_duration_seconds=mm.get("capture_duration_seconds", config.monitor_mode.capture_duration_seconds),
        )

    return config


def _apply_env_overrides(config: AppConfig) -> AppConfig:
    """Apply environment variable overrides to configuration.

    Environment variables follow the pattern BTWIFI_<SECTION>_<KEY>.

    Args:
        config: Configuration to override.

    Returns:
        Configuration with env var overrides applied.
    """
    if db_url := os.environ.get("DATABASE_URL"):
        config.database.url = db_url

    if interval := os.environ.get("BTWIFI_SCAN_INTERVAL"):
        try:
            config.scan.interval_seconds = int(interval)
        except ValueError:
            logger.warning("Invalid BTWIFI_SCAN_INTERVAL: %s", interval)

    if continuous := os.environ.get("BTWIFI_CONTINUOUS"):
        config.scan.continuous = continuous.lower() in ("1", "true", "yes")

    if gap := os.environ.get("BTWIFI_GAP_SECONDS"):
        try:
            config.scan.gap_seconds = int(gap)
        except ValueError:
            logger.warning("Invalid BTWIFI_GAP_SECONDS: %s", gap)

    return config
