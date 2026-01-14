# purpl (Network Test Control Center)

A powerful, interactive, and automated CLI tool for Red Teaming and Network Security auditing, written in Rust. purpl acts as a central control proxy, orchestrating industry-standard tools like Nmap and Wifite into a streamlined, safe, and efficient workflow.

## Key Features

*   **Multi-Tool Automation:**
    *   **Nmap:** Automated scanning profiles (Stealth, Quick, Intense, Paranoid) with intelligent optimization for large networks (Class A/B).
    *   **Wifite:** Automated WiFi auditing wrapper with monitor mode handling and cleanup.
    *   **Tcpdump:** Integrated packet sniffing with real-time traffic analysis and reporting.
*   **Evasion and Anonymity:**
    *   **Proxychains Integration:** Toggleable global proxy support to route all scans through Tor/SOCKS proxies for anonymity.
    *   **Smart Privilege Handling:** Automatically detects root requirements. Allows standard users to run safe scans or safely elevates privileges (via sudo) only when necessary with secure validation.
*   **Structured Reporting:**
    *   Parses raw XML/JSON output into readable CLI reports.
    *   Displays organized Host info: IPs (v4/v6), OS, MAC, and Service details.
    *   Auto-generates Google Search links for discovered service versions to quickly find exploits.
*   **History and Persistence:**
    *   Automatically logs every scan execution (timestamp, target, mode, status).
    *   View past scan reports interactively.
*   **Optimization:**
    *   **Class A Support:** Auto-detects large ranges (/8) and switches to optimized "Mass Scan" settings (no DNS, aggressive timing, rate-limited) to prevent timeouts.
*   **Robust Architecture:**
    *   **Testable Design:** Built with dependency injection to allow comprehensive unit testing without side effects.
    *   **High Coverage:** Maintains >60% code coverage to ensure reliability.

## Dependencies

Ensure the following tools are installed on your system:

*   **Nmap:** Core network scanner.
*   **Wifite:** WiFi auditing tool (requires Python).
*   **Tshark (Wireshark-CLI):** Required by Wifite for packet analysis.
*   **Airmon-ng / Aircrack-ng:** Required for WiFi monitor mode and cracking.

## Usage

**Interactive Mode:**
```bash
./purpl_bin
```

**CLI One-Liners:**
```bash
# Stealth scan a target (will prompt for sudo if needed)
./purpl_bin --nmap 192.168.1.10

# Scan through Proxychains
./purpl_bin --nmap 10.0.0.0/8 --proxy

# Run WiFi Audit
./purpl_bin --wifite wlan0
```

## Build

```bash
cargo build --release
```

## Testing

Run the unit tests:
```bash
cargo test
```

## Roadmap
Improve wifite implementation
