# NT_TEST: Implementation Guide & Development Manual

This document provides a comprehensive guide to the architecture, implementation details, and step-by-step build process of the `nt_test` Network Testing & Automation Tool.

## 1. Core Philosophy & Architecture

`nt_test` is designed as a unified command-line interface (CLI) that acts as an intelligent wrapper around industry-standard security tools (`nmap`, `wifite`, `tcpdump`, `gobuster`, `hydra`, `searchsploit`).

### Key Design Principles:
1.  **Safety & Validation:** Never run a dangerous command without validation (e.g., sudo checks, target format validation).
2.  **Profile-Based Execution:** Instead of asking users for raw flags, offer "Profiles" (e.g., "Stealth Scan", "WPS Only") that map to optimized flag sets.
3.  **Unified Reporting:** Consolidate outputs (XML, JSON, Text) into a single, human-readable terminal report.
4.  **Persistence:** Save scan history and results automatically to a structured directory hierarchy.

### Directory Structure
```
nt_test/
├── src/
│   ├── main.rs       # Entry point, CLI menu, and argument parsing
│   ├── nmap.rs       # Nmap execution logic & profiles
│   ├── web.rs        # Web Enumeration (Gobuster)
│   ├── exploit.rs    # Exploit Search (Searchsploit)
│   ├── brute.rs      # Credential Access (Hydra)
│   ├── wifi.rs       # Wifite execution logic & profiles
│   ├── sniffer.rs    # Tcpdump logic, real-time parsing, & reporting
│   ├── report.rs     # Report parsing (XML, JSON, TXT) & display
│   └── history.rs    # History tracking (JSON based)
├── scans/            # Output directory
│   ├── <target_ip>/  # For Nmap scans
│   ├── web/          # For Gobuster results
│   ├── brute/        # For Hydra results
│   ├── wifi/         # For Wifi audits
│   └── packets/      # For Packet captures
└── Cargo.toml        # Dependencies
```

---

## 2. Dependencies

The project relies on the following Rust crates:
- `clap`: Command-line argument parsing.
- `colored`: Terminal text coloring.
- `indicatif`: Progress bars and spinners.
- `regex`: Output parsing.
- `serde` & `serde_json`: Serialization for history and report parsing.
- `roxmltree`: Lightweight XML parsing for Nmap results.
- `chrono`: Date and time formatting.
- `libc`: System calls (checking root privileges).

---

## 3. Step-by-Step Implementation Guide

### Phase 1: Foundation & Network Recon (`nmap.rs`)
*   **Tool:** `nmap`
*   **Profiles:** "Stealth", "Intense", "Mass Scan".
*   **Logic:** Wraps `nmap` execution with `sudo` checks for SYN scans.
*   **Output:** `scans/<target>/<date>/`.

### Phase 2: Web Enumeration (`web.rs`)
*   **Tool:** `gobuster`
*   **Logic:**
    - Validates target URL scheme.
    - Automatically finds wordlists in standard Kali paths (`/usr/share/wordlists`).
    - Offers "Quick" vs "Deep" profiles based on wordlist size.
*   **Output:** Streamed to file `scans/web/<target>/<date>/gobuster.txt`.

### Phase 3: Exploit Search (`exploit.rs`)
*   **Tool:** `searchsploit` (Exploit-DB)
*   **Logic:**
    - Parses previous Nmap XML reports to find `<service product="..." version="...">`.
    - Automatically queries `searchsploit` for matches.
    - Displays relevant exploits directly in the terminal.
*   **Output:** Terminal display of exploit titles and paths.

### Phase 4: Credential Access (`brute.rs`)
*   **Tool:** `hydra`
*   **Logic:**
    - Supports multiple protocols (SSH, FTP, RDP).
    - Auto-detects wordlists (Seclists, Metasploit).
    - "Quick Spray" profile for testing top credentials against a target.
*   **Output:** `scans/brute/<target>/<date>/hydra.txt`.

### Phase 5: WiFi Automation (`wifi.rs`)
*   **Tool:** `wifite`
*   **Logic:**
    - Automates `airmon-ng` checks and MAC randomization.
    - **Persistence:** Moves `hs/` directory to `scans/wifi/<date>/` for permanent storage.
    - **Profiles:** "WPS Only", "Handshake Capture", "5GHz".

### Phase 6: Packet Sniffer (`sniffer.rs`)
*   **Tool:** `tcpdump`
*   **Logic:**
    - Runs `tcpdump -l -A` to capture ASCII payload.
    - Heuristically decodes HTTP, FTP, and DNS traffic in real-time.
    - **Reporting:** Generates a "Beautiful Report" (`report.txt`) stored in `scans/packets/<date>/`.

### Phase 7: Unified Reporting (`report.rs`)
*   **Logic:** Centralized parser for all tool outputs.
    - **Nmap:** Parses XML, highlights vulnerabilities (`--script vuln`).
    - **Wifite:** Parses JSON, displays cracked keys and encryption type.
    - **Sniffer:** Displays formatted text report.
    - **Links:** Generates research links for discovered services.

### Phase 8: Bluetooth Arsenal (`bluetooth.rs`)
*   **Tools:** `BlueZ` suite (`hcitool`, `sdptool`, `l2ping`).
*   **Logic:**
    - **Discovery:** Scans for visible (Classic) and Low Energy (LE) devices.
    - **Enumeration:** Queries SDP to identify device types (Audio, Phone, Peripheral).
    - **Offensive:** Implements L2CAP ping flooding for stress testing.
    - **Persistence:** Saves scan results to `scans/bluetooth/<date>/`.

---

## 4. Building & Running

### Prerequisites
- **Rust Toolchain:** `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **External Tools:** `nmap`, `wifite`, `tcpdump`, `gobuster`, `hydra`, `searchsploit`, `airmon-ng`, `macchanger`.

### Build
```bash
cargo build --release
```

### Run
```bash
# Run from target directory
./target/release/nt_test
```

---

## 5. Security & Safety

- **Root Privileges:** The tool requests `sudo` for low-level operations. It validates credentials using `sudo -v` before starting long-running tasks.
- **Result Isolation:** Each scan is timestamped and isolated.
- **Proxychains:** The global `proxy` flag wraps commands with `proxychains` for network pivoting.
- **Input Sanitization:** Command injection is prevented by using `Command::args`.