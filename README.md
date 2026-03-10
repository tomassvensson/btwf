# BtWiFi - Device Visibility Tracker

Track which WiFi and Bluetooth devices are and were visible, when, and how strongly.

## Overview

BtWiFi uses a USB WiFi adapter (Goshyda AR9271) to scan for nearby wireless devices and track their visibility over time. It translates MAC addresses to human-readable vendor/brand names and stores visibility windows in a local SQLite database.

## Features

- **WiFi Network Scanning** — Discovers nearby WiFi networks and access points
- **Bluetooth Device Scanning** — Discovers nearby Bluetooth devices
- **Vendor Identification** — Translates MAC addresses to manufacturer names using the IEEE OUI database
- **Visibility Tracking** — Stores when devices were first/last seen with signal strength
- **Human-readable Output** — Displays results in a formatted table

## Technology Stack

- **Language:** Python 3.10+
- **Database:** SQLite via SQLAlchemy
- **WiFi Scanning:** Windows Native WiFi API (`netsh`), with Scapy support for deeper analysis
- **Bluetooth Scanning:** Windows Bluetooth API
- **OUI Lookup:** IEEE MA-L (OUI) database
- **Testing:** pytest with coverage

## Quick Start

```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python -m src.main
```

## Project Structure

```
btwf/
├── src/
│   ├── __init__.py
│   ├── main.py              # Entry point
│   ├── models.py             # SQLAlchemy database models
│   ├── database.py           # Database session management
│   ├── wifi_scanner.py       # WiFi scanning module
│   ├── bluetooth_scanner.py  # Bluetooth scanning module
│   ├── oui_lookup.py         # MAC-to-vendor translation
│   ├── device_tracker.py     # Visibility window tracking logic
│   └── data/
│       └── .gitkeep
├── tests/
│   ├── __init__.py
│   ├── test_models.py
│   ├── test_database.py
│   ├── test_wifi_scanner.py
│   ├── test_bluetooth_scanner.py
│   ├── test_oui_lookup.py
│   └── test_device_tracker.py
├── docs/
│   └── adr/
│       └── 001-technology-choice.md
├── .editorconfig
├── .env.example
├── .gitignore
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Architecture

See [ADR-001](docs/adr/001-technology-choice.md) for the technology choice rationale.

## Security

- Scanned devices are never given access to the network or computer
- The system operates in read-only/passive scanning mode
- No connections are established with discovered devices

## License

Private project — not yet open source.
