# nt_test (Network Test Control Center)

A powerful, interactive, and automated CLI tool for Red Teaming and Network Security auditing, written in Rust. nt_test acts as a central control proxy, orchestrating industry-standard tools like Nmap and Wifite into a streamlined, safe, and efficient workflow.

Originally a Python script (lab_tool), this project has been completely rewritten in Rust for performance, reliability, and modularity.

## Key Features

*   **Multi-Tool Automation:**
    *   **Nmap:** Automated scanning profiles (Stealth, Quick, Intense, Paranoid) with intelligent optimization for large networks (Class A/B).
    *   **Wifite:** Automated WiFi auditing wrapper with monitor mode handling and cleanup.
    *   **Tcpdump:** Integrated packet sniffing (via legacy script support).
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

## Usage

**Interactive Mode:**
```bash
./nt_test_bin
```

**CLI One-Liners:**
```bash
# Stealth scan a target (will prompt for sudo if needed)
./nt_test_bin --nmap 192.168.1.10

# Scan through Proxychains
./nt_test_bin --nmap 10.0.0.0/8 --proxy

# Run WiFi Audit
./nt_test_bin --wifite wlan0
```

## Build

```bash
cargo build --release
```
