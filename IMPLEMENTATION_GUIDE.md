# NT_TEST: Implementation Guide & Development Manual

This document provides a comprehensive guide to the architecture, implementation details, and step-by-step build process of the `nt_test` Network Testing & Automation Tool.

## 1. Core Philosophy & Architecture

`nt_test` is designed as a unified command-line interface (CLI) that acts as an intelligent wrapper around industry-standard security tools (`nmap`, `wifite`, `tcpdump`, `gobuster`, `hydra`, `searchsploit`).

### Key Design Principles:
1.  **Safety & Validation:** Never run a dangerous command without validation. Checks root privileges abstractly via `CommandExecutor`.
2.  **Profile-Based Execution:** Instead of asking users for raw flags, offer "Profiles" (e.g., "Stealth Scan", "WPS Only").
3.  **Unified Reporting:** Consolidate outputs (XML, JSON, Text) into a single, human-readable terminal report.
4.  **Persistence:** Save scan history and results automatically to a structured directory hierarchy.
5.  **Testability:** All components use Dependency Injection (`CommandExecutor`, `IoHandler`) to allow unit testing without executing real commands or blocking on user input.

### Directory Structure
```
nt_test/
├── src/
│   ├── main.rs       # Entry point, interactive loop, and dependency wiring
│   ├── executor.rs   # Command execution abstraction (Shell vs Mock)
│   ├── io_handler.rs # Input/Output abstraction (Real vs Mock)
│   ├── nmap.rs       # Nmap execution logic & profiles
│   ├── web.rs        # Web Enumeration (Gobuster)
│   ├── exploit.rs    # Exploit Search (Searchsploit)
│   ├── brute.rs      # Credential Access (Hydra)
│   ├── poison.rs     # LAN Poisoning (Responder)
│   ├── wifi.rs       # Wifite execution logic & profiles
│   ├── bluetooth.rs  # Bluetooth Discovery & Attacks
│   ├── sniffer.rs    # Tcpdump logic with live stream parsing
│   ├── report.rs     # Report parsing (XML, JSON, TXT) & display
│   └── history.rs    # History tracking (JSON based)
├── scans/            # Output directory
│   ├── <target_ip>/  # For Nmap scans
│   ├── web/          # For Gobuster results
│   ├── brute/        # For Hydra results
│   ├── poison/       # For Responder logs
│   ├── bluetooth/    # For Bluetooth scans
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
- `libc`: System calls (checking root privileges in RealExecutor).

---

## 3. Step-by-Step Implementation Guide

### Phase 1: Foundation & Network Recon (`nmap.rs`)
*   **Tool:** `nmap`
*   **Profiles:** "Stealth", "Intense", "Mass Scan".
*   **Logic:** Uses `execute_silent` for Deep Scan to avoid interfering with progress bars.
*   **Output:** `scans/<target>/<date>/`.

### Phase 2: Web Enumeration (`web.rs`)
*   **Tool:** `gobuster`
*   **Logic:** Validates URL, auto-detects wordlists, profiles.
*   **Output:** `scans/web/<target>/<date>/gobuster.txt`.

### Phase 3: Exploit Search (`exploit.rs`)
*   **Tool:** `searchsploit`
*   **Logic:** Parses Nmap XML, queries Exploit-DB via `execute_output`.
*   **Output:** Terminal display.

### Phase 4: Credential Access (`brute.rs`)
*   **Tool:** `hydra`
*   **Logic:** Protocol selection, wordlist management.
*   **Output:** `scans/brute/<target>/<date>/hydra.txt`.

### Phase 5: LAN Poisoning (`poison.rs`)
*   **Tool:** `responder`
*   **Logic:** Requires Root (checked via `executor.is_root()`). Moves logs after execution.
*   **Output:** `scans/poison/<date>/logs/`.

### Phase 6: WiFi Automation (`wifi.rs`)
*   **Tool:** `wifite`
*   **Logic:** Automates `airmon-ng` setup/teardown. Requires Root.
*   **Output:** `scans/wifi/<date>/cracked.json`.

### Phase 7: Bluetooth Arsenal (`bluetooth.rs`)
*   **Tools:** `BlueZ` suite.
*   **Logic:** Discovery and attacks.
*   **Output:** `scans/bluetooth/<date>/scan.txt`.

### Phase 8: Packet Sniffer (`sniffer.rs`)
*   **Tool:** `tcpdump`
*   **Logic:** Uses `spawn_stdout` to stream and parse output in real-time without blocking.
*   **Output:** `scans/packets/<date>/report.txt` and `capture.pcap`.

### Phase 9: Unified Reporting (`report.rs`)
*   **Logic:** Centralized parser using `IoHandler` for output.

---

## 4. Building & Running

### Build
```bash
cargo build --release
```

### Run
```bash
./target/release/nt_test
```

### Testing
Run the comprehensive unit test suite:
```bash
cargo test
```
The project maintains >60% code coverage.
