# BtWiFi - Device Visibility Tracker

Track which WiFi, Bluetooth, and network devices are and were visible, when, and how strongly.

## Overview

BtWiFi uses multiple discovery protocols to scan for nearby wireless and network devices, tracking their visibility over time. It translates MAC addresses to human-readable vendor/brand names and stores visibility windows in a local SQLite database.

## Features

- **WiFi Network Scanning** — Discovers nearby WiFi networks and access points
- **Bluetooth Device Scanning** — Discovers nearby Bluetooth devices
- **mDNS/Bonjour Discovery** — Finds devices advertising mDNS services (printers, IoT, Apple devices)
- **SSDP/UPnP Discovery** — Discovers UPnP devices on the network
- **NetBIOS Name Resolution** — Resolves Windows/SMB device names
- **ARP Network Discovery** — Discovers devices visible in the ARP table
- **Device Categorization** — Automatically categorizes devices (phone, laptop, IoT, router, etc.)
- **Device Fingerprinting** — Identifies device type, OS, and model from multiple data sources
- **Vendor Identification** — Translates MAC addresses to manufacturer names using the IEEE OUI database
- **Visibility Tracking** — Stores when devices were first/last seen with signal strength
- **Whitelist Management** — Tag known devices with custom names and trust levels
- **Alert System** — Log alerts when new unknown devices appear on the network
- **Continuous Scanning** — Run repeated scans with configurable intervals
- **YAML Configuration** — Configure all scanner options through `config.yaml`
- **Human-readable Output** — Displays results in a formatted table with categories and vendor names
- **Docker Support** — Dockerfile and docker-compose.yml for containerized deployment

## Technology Stack

- **Language:** Python 3.10+
- **Database:** SQLite via SQLAlchemy
- **WiFi Scanning:** Windows Native WiFi API (`netsh`)
- **Bluetooth Scanning:** Windows Bluetooth API via PowerShell
- **ARP Discovery:** `ip neigh` (Linux) / `arp -a` (Windows)
- **mDNS Discovery:** zeroconf library
- **OUI Lookup:** IEEE MA-L (OUI) database via mac-vendor-lookup
- **Configuration:** PyYAML
- **Testing:** pytest with 324 tests, 96% coverage
- **REST API:** FastAPI with OpenAPI/Swagger UI
- **Web Dashboard:** HTMX server-side dashboard at `/`
- **Metrics:** Prometheus-compatible `/metrics` endpoint
- **Linting:** ruff (lint + format)
- **Type Checking:** mypy
- **CI/CD:** GitHub Actions (lint, test matrix, Trivy, CodeQL)
- **Code Quality:** SonarQube

## Quick Start

```bash
# Create virtual environment
python3 -m venv .venv

# Activate (Linux / WSL / macOS)
source .venv/bin/activate
# Activate (Windows PowerShell)
# .venv\Scripts\Activate.ps1

# Install dependencies
pip install -e ".[dev]"

# Create your config
cp config.yaml.example config.yaml
# Edit config.yaml to your needs
python -m src.main
```

> **WSL / Linux note:** WiFi and Bluetooth scanners use Windows-only APIs
> (`netsh`, PowerShell). On Linux or WSL, set `wifi_enabled`, `bluetooth_enabled`,
> and `ble_enabled` to `false` in `config.yaml`. The ARP, mDNS, SSDP, NetBIOS,
> and IPv6 scanners work cross-platform. Under WSL2, enable `ping_sweep` with
> your LAN subnet to discover devices beyond the virtual NAT gateway.

## Configuration

Copy `config.yaml.example` to `config.yaml` and customize:

```yaml
scan:
  wifi_enabled: true
  bluetooth_enabled: true
  arp_enabled: true
  mdns_enabled: true
  ssdp_enabled: true
  netbios_enabled: true
  continuous: false
  interval_seconds: 60

whitelist:
  devices:
    - mac: "AA:BB:CC:DD:EE:FF"
      name: "My Router"
      trusted: true
      category: "router"

alert:
  enabled: true
  log_file: "alerts.log"
```

## Project Structure

```
btwf/
├── src/
│   ├── __init__.py
│   ├── main.py              # Entry point and scan orchestration
│   ├── models.py             # SQLAlchemy database models
│   ├── database.py           # Database session management
│   ├── config.py             # YAML configuration loader
│   ├── wifi_scanner.py       # WiFi scanning (netsh)
│   ├── bluetooth_scanner.py  # Bluetooth scanning (PowerShell)
│   ├── network_discovery.py  # ARP table scanning
│   ├── mdns_scanner.py       # mDNS/Bonjour service discovery
│   ├── ssdp_scanner.py       # SSDP/UPnP device discovery
│   ├── netbios_scanner.py    # NetBIOS name resolution
│   ├── oui_lookup.py         # MAC-to-vendor translation
│   ├── device_tracker.py     # Visibility window tracking
│   ├── categorizer.py        # Device categorization engine
│   ├── fingerprint.py        # Device fingerprinting
│   ├── whitelist.py          # Known device management
│   ├── alert.py              # New device alert system
│   ├── api.py                # FastAPI REST API + HTMX dashboard
│   ├── metrics.py            # Prometheus metrics
│   └── data/
│       └── .gitkeep          # IEEE OUI CSV downloaded here
├── tests/                    # pytest test suite
│   ├── e2e/                  # Playwright E2E browser tests
│   │   └── test_dashboard_e2e.py
│   ├── test_database_integration.py  # TestContainers PostgreSQL tests
│   ├── test_main.py
│   ├── test_config.py
│   ├── test_categorizer.py
│   ├── test_whitelist.py
│   ├── test_alert.py
│   ├── test_fingerprint.py
│   ├── test_mdns_scanner.py
│   ├── test_ssdp_scanner.py
│   ├── test_netbios_scanner.py
│   ├── test_wifi_scanner.py
│   ├── test_bluetooth_scanner.py
│   ├── test_network_discovery.py
│   ├── test_oui_lookup.py
│   └── test_database.py
├── .github/
│   └── workflows/
│       ├── ci.yml            # GitHub Actions CI pipeline
│       └── oui-update.yml    # Weekly IEEE OUI database refresh
├── docs/
│   └── adr/
│       └── 001-technology-choice.md
├── Dockerfile
├── docker-compose.yml
├── config.yaml.example
├── pyproject.toml
├── requirements.txt
├── sonar-project.properties
└── README.md
```

## Architecture

See [ADR-001](docs/adr/001-technology-choice.md) for the technology choice rationale.

## Security

- Scanned devices are never given access to the network or computer
- The system operates in read-only/passive scanning mode
- No connections are established with discovered devices
- See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy

## REST API & Web Dashboard

BtWiFi ships a FastAPI service that provides a live web dashboard and a
versioned JSON API.

### Starting the API server

```bash
# Development (auto-reload on code changes)
uvicorn src.api:app --reload

# Production
uvicorn src.api:app --host 0.0.0.0 --port 8000
```

| URL | Description |
|-----|-------------|
| `http://localhost:8000/` | Live device dashboard (HTMX) |
| `http://localhost:8000/docs` | Swagger / OpenAPI UI |
| `http://localhost:8000/redoc` | ReDoc UI |
| `http://localhost:8000/metrics` | Prometheus metrics |

### API Endpoints (v1)

All JSON endpoints are under `/api/v1/`.

#### Health check

```bash
curl http://localhost:8000/api/v1/health
# {"status":"ok","version":"0.1.0"}
```

#### List devices (paginated)

```bash
# First page, default page size (20)
curl http://localhost:8000/api/v1/devices

# Explicit pagination
curl "http://localhost:8000/api/v1/devices?page=1&page_size=10"
```

Response:
```json
{
  "devices": [
    {
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "device_type": "wifi",
      "vendor": "Apple Inc.",
      "name": null,
      "reconnect_count": 3,
      "created_at": "2024-01-01T12:00:00",
      "updated_at": "2024-01-01T13:00:00"
    }
  ],
  "total": 42,
  "page": 1,
  "page_size": 10
}
```

#### Get a single device

```bash
curl http://localhost:8000/api/v1/devices/AA:BB:CC:DD:EE:FF
```

#### Visibility windows for a device

```bash
curl http://localhost:8000/api/v1/devices/AA:BB:CC:DD:EE:FF/windows
```

Response:
```json
[
  {
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "first_seen": "2024-01-01T12:00:00",
    "last_seen": "2024-01-01T13:00:00",
    "signal_strength_dbm": -65,
    "scan_count": 5
  }
]
```

#### Summary statistics

```bash
curl http://localhost:8000/api/v1/summary
# {"total_devices":42,"active_last_hour":7,"device_types":{"wifi":30,"bluetooth":12}}
```

#### HTMX table fragment (for dashboard auto-refresh)

```bash
curl "http://localhost:8000/api/v1/devices-table?page=1"
# Returns an HTML fragment suitable for HTMX injection
```

#### Prometheus metrics

```bash
curl http://localhost:8000/metrics
```

### Rate Limits

The `/api/v1/devices` endpoint is rate-limited to **100 requests per minute**
per IP address (via slowapi). Exceeding the limit returns HTTP `429 Too Many Requests`.



