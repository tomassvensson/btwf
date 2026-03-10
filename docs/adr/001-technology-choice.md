# ADR-001: Technology Choice

## Status

Accepted

## Date

2026-03-09

## Context

We need to build a system that:
- Scans for WiFi and Bluetooth devices using a USB WiFi adapter (Goshyda AR9271, ath9k_htc chipset)
- Translates device identifiers into human-readable names
- Stores visibility windows in a database
- Is maintainable and extensible for medium-to-long term development

## Decision

**Language: Python 3.10+**

**Key Libraries:**
- **SQLAlchemy** — ORM for database access, supports SQLite now and can migrate to PostgreSQL later
- **Scapy** — Packet capture and analysis (for future monitor mode support)
- **mac-vendor-lookup** — IEEE OUI database for MAC-to-vendor translation
- **pytest** — Testing framework with coverage support
- **zeroconf** — mDNS service discovery for friendly device names

**Database: SQLite** (via SQLAlchemy, easily swappable)

**Scanning approach on Windows:**
- `netsh wlan show networks mode=bssid` — Reliable WiFi network discovery
- Windows Bluetooth API via PowerShell — Bluetooth device discovery
- ARP table inspection — Local network device discovery
- Passive only — no connections established with discovered devices

## Alternatives Considered

### Go
- Pros: Fast, compiled, good concurrency
- Cons: Smaller ecosystem for network analysis, less library support for WiFi scanning

### Rust
- Pros: Memory safety, performance
- Cons: Steeper learning curve, smaller ecosystem for this domain

### Node.js/TypeScript
- Pros: Familiar, good async support
- Cons: Less suitable for low-level network operations, fewer WiFi/BT scanning libraries

### C/C++
- Pros: Direct hardware access, maximum performance
- Cons: Memory management burden, slower development cycles

## Consequences

- Python provides the richest ecosystem for network analysis and device discovery
- SQLAlchemy allows database-agnostic development; can migrate from SQLite to PostgreSQL when needed
- The scanning approach is passive-only, ensuring no security risks to scanned devices
- Cross-platform potential exists but initial focus is Windows (user's current OS)
- Python's dynamic typing requires careful testing; mitigated by type hints and pytest
