# NT_TEST: Implementation Guide & Development Manual

This document provides a comprehensive guide to the architecture, implementation details, and step-by-step build process of the `nt_test` Network Testing & Automation Tool.

## 1. Core Philosophy & Architecture

`nt_test` is designed as a unified command-line interface (CLI) that acts as an intelligent wrapper around industry-standard security tools (`nmap`, `wifite`, `tcpdump`).

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
│   ├── wifi.rs       # Wifite execution logic & profiles
│   ├── sniffer.rs    # Tcpdump logic, real-time parsing, & reporting
│   ├── report.rs     # Report parsing (XML, JSON, TXT) & display
│   └── history.rs    # History tracking (JSON based)
├── scans/            # Output directory
│   ├── <target_ip>/  # For Nmap scans
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

### Phase 1: Foundation (CLI & History)

1.  **Project Setup:**
    ```bash
    cargo new nt_test
    cd nt_test
    # Add dependencies to Cargo.toml
    ```
2.  **Entry Point (`main.rs`):**
    - Define the `Cli` struct using `clap`.
    - Implement an interactive loop that clears the screen and prints a banner.
    - Implement the command dispatch logic.
3.  **History Module (`history.rs`):**
    - Define a `HistoryEntry` struct (timestamp, mode, target, status).
    - Implement `append_history` to read/write `scan_history.json`.

### Phase 2: Nmap Integration (`nmap.rs`)

1.  **Profiles:** Create a `ScanProfile` struct. Define presets like "Stealth", "Intense", "Mass Scan".
2.  **Execution:**
    - Use `std::process::Command` to run `nmap`.
    - Wrap execution with `sudo` checks if the profile requires root (SYN scans).
    - Implement intelligent defaults (e.g., fallback to `-sT` if non-root).
3.  **Output Management:**
    - Generate path: `scans/<target>/<date>/`.
    - Run Nmap with `-oA` to save all formats.

### Phase 3: WiFi Automation (`wifi.rs`)

1.  **Profiles:** Define `WifiProfile` (e.g., "WPS Only", "Handshake Capture").
2.  **Workflow:**
    - **Check Root:** WiFi audit requires root.
    - **Kill Processes:** Run `airmon-ng check kill`.
    - **Mac Changer:** Randomize MAC for anonymity.
    - **Monitor Mode:** Enable monitor mode on the interface.
    - **Execution:** Run `wifite` with profile flags.
    - **Cleanup:** Stop monitor mode, restart NetworkManager.
    - **Artifacts:** Move `hs/` directory to `scans/wifi/<date>/`.

### Phase 4: Packet Sniffer (`sniffer.rs`)

1.  **Real-time Processing:**
    - Run `tcpdump -l -A` (Line buffered, ASCII).
    - Capture `stdout` in a separate thread.
2.  **Heuristic Parsing:**
    - Use Regex to identify packet headers (`Time IP Src > Dst`).
    - Attempt to decode payload (HTTP, plain text credentials).
3.  **Reporting:**
    - Write a "Beautiful Report" to `report.txt` while also updating the screen.
    - Save raw `.pcap` if needed (optional implementation choice).

### Phase 5: Unified Reporting (`report.rs`)

1.  **Discovery:**
    - Iterate through `scans/` directory.
    - Identify scan types based on content (Nmap XML, Wifite JSON, Sniffer TXT).
2.  **Parsing:**
    - **Nmap:** Use `roxmltree` to extract Host, OS, and Services.
    - **Wifite:** Use `serde_json` to parse `cracked.json`.
    - **Sniffer:** Read `report.txt` directly.
3.  **Display:**
    - Format the parsed data into tables using `println!` and `colored`.

---

## 4. Building & Running

### Prerequisites
- **Rust Toolchain:** `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **External Tools:** `nmap`, `wifite`, `tcpdump`, `airmon-ng`, `macchanger`.

### Build
```bash
cargo build --release
```

### Run
```bash
# Run from target directory
./target/release/nt_test

# Or via cargo
cargo run
```

### Usage Examples
1.  **Nmap:** Select "Network Scan", enter IP `192.168.1.1`. Choose "Stealth Scan".
2.  **WiFi:** Select "WiFi Audit", enter `wlan0`. Choose "WPS Only".
3.  **Report:** Select "View Scan Results", navigate to the target/date, and view the parsed output.

---

## 5. Security Considerations

- **Root Privileges:** The tool requests `sudo` for low-level operations. It does NOT cache credentials but relies on the system's `sudo` timeout.
- **Proxychains:** The global `proxy` flag wraps commands with `proxychains` for network pivoting/anonymity. Ensure `proxychains.conf` is configured.
- **Input Sanitization:** While Rust handles memory safety, command injection is prevented by using `Command::args` (vector of strings) rather than shell string interpolation.

