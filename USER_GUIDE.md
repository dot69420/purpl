# PURPL: Purple Team Helper Tool - User Guide

## 1. Introduction

PURPL (Purple Team Helper Tool) is a comprehensive Command Line Interface (CLI) utility designed for network security assessments, penetration testing, and red/blue team exercises. It integrates various industry-standard security tools (Nmap, Gobuster, Ffuf, SQLMap, Curl, Hydra, Searchsploit, Tcpdump, Responder, Wifite, Bluetooth tools) into a unified and intuitive workflow.

PURPL offers both an interactive menu-driven interface for guided operations and a powerful command-line interface for automation and scripting. Its "Always a Job" architecture ensures consistent handling of tasks, whether executed in the foreground or background, with robust output management.

## 2. Installation

To build and install PURPL, you will need a Rust toolchain.
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/purpl.git # Replace with actual repo URL
    cd purpl
    ```
2.  **Build the project:**
    ```bash
    cargo build --release
    ```
    The executable will be located at `target/release/purpl`. You may add this path to your system's `PATH` environment variable for easier access.

## 3. Getting Started

PURPL can be operated in two primary modes: Interactive (menu-driven) and Command Line Interface (CLI).

### 3.1. Interactive Mode

This is the recommended mode for most users, providing a guided experience through PURPL's functionalities.

To start interactive mode, simply run the executable without any arguments:
```bash
./target/release/purpl
```
You will be greeted by the main menu with an ASCII art banner and a list of tool categories. Navigate by typing the number corresponding to your choice and pressing Enter.

### 3.2. Command Line Interface (CLI) Mode

For automation, scripting, or quick one-off tasks, PURPL supports direct CLI invocation for most tools. Use the `--help` flag for a list of available commands and options.

```bash
./target/release/purpl --help
```
**General CLI Syntax:**
```bash
./target/release/purpl --<tool_name> <target_or_interface> [OPTIONS]
```
**Common CLI Options:**
*   `--proxy`: Route tool traffic through Proxychains (if configured on your system).
*   `--args "<extra_tool_args>"`: Pass additional, tool-specific arguments directly.
*   `--wordlist <path>`: Specify a custom wordlist for tools like Gobuster or Ffuf.

**Example CLI Usage:**
```bash
# Nmap scan on a target IP
./target/release/purpl --nmap 192.168.1.1 --args "-sV -sC"

# Web enumeration with Gobuster
./target/release/purpl --web http://example.com --wordlist wordlists/common.txt

# Active exploitation with SQLMap
./target/release/purpl --exploit http://site.com/vuln.php --tool sqlmap --args "--dbs --batch"
```

## 4. Core Concepts

### 4.1. "Always a Job" Architecture

PURPL operates on an "Always a Job" principle. Every significant operation (scan, attack, fuzz) is treated as a "Job." This architecture ensures:
*   **Separation of Concerns:** Configuration (interactive setup of a task) is distinct from Execution (running the task).
*   **Consistency:** All tools adhere to a predictable workflow for setup and execution.
*   **Manageability:** Jobs can be run in the foreground or background, and their status and output can be monitored.

### 4.2. Foreground vs. Background Execution

After configuring a tool, you will often be prompted to run the task in the background (`y/N`).
*   **Foreground (N):** The tool executes directly in your terminal. You see real-time output, and the CLI blocks until the task completes. Once finished, you'll be prompted to "Press Enter" to return to the menu.
*   **Background (y):** The tool is spawned in a separate thread, allowing you to continue interacting with the PURPL CLI. Output is captured internally and can be viewed later via the Dashboard.

### 4.3. Output Management

All tool outputs (both foreground and background jobs) are intelligently captured and saved:
*   **Persistent Storage:** For most scanning and exploitation tools, detailed reports and raw outputs are saved to the `scans/` directory, organized by tool, target, and timestamp (`scans/<tool>/<target>/<YYYYMMDD_HHMMSS>/`).
*   **Dashboard Integration:** The Dashboard provides a unified view of both active (in-memory) jobs and historical (filesystem) scan results.

### 4.4. Proxychains Integration

PURPL natively integrates with `proxychains` (if installed and configured on your system).
*   **Interactive Mode:** You can toggle Proxychains `ON/OFF` from the main menu. When `ON`, all tools supporting it will automatically route their traffic through your configured proxies.
*   **CLI Mode:** Use the `--proxy` flag (e.g., `./purpl --nmap 192.168.1.1 --proxy`).

## 5. Main Menu & Tools

The interactive main menu provides access to different categories of security tools.

### 5.1. Network Recon (Nmap)

Comprehensive port scanning, service detection, OS fingerprinting, and vulnerability scripting.

*   **Configuration & Profiles:** Nmap offers various scan profiles (Stealth & Vuln, Connect Scan, Quick Audit, Intense Scan, Paranoid) optimized for different scenarios. It also handles custom port specifications and host discovery options.
*   **Sudo Privileges:** Many powerful Nmap scans (e.g., SYN scans, OS detection) require root privileges. PURPL will prompt you to attempt `sudo` elevation if needed. If authentication fails, it will provide detailed error messages from `sudo` itself.
*   **Usage Examples (Interactive):**
    1.  Select `Network Recon (Nmap)` from the main menu.
    2.  Enter the target IP address.
    3.  Choose a scan profile (e.g., `Stealth & Vuln`).
    4.  If prompted for `sudo` (and not already root), type `y` to elevate.
    5.  Decide whether to run in the background.
*   **Usage Examples (CLI):**
    ```bash
    ./target/release/purpl --nmap 192.168.1.1 --args "-Pn -sV" # Nmap with args
    ./target/release/purpl --nmap 192.168.1.1 --proxy # Nmap via proxychains
    ```

### 5.2. Web Arsenal (Gobuster, Ffuf)

Tools for web enumeration and fuzzing.

#### Gobuster (Web Enumeration)
Directory and file brute-forcing to discover hidden paths, files, and subdomains.
*   **Configuration:** Specify target URL, choose scan modes (dir, file, vhost), and provide wordlists.
*   **Usage Examples (Interactive):**
    1.  Select `Web Arsenal` -> `Web Enumeration - Gobuster`.
    2.  Enter the Target URL (e.g., `http://example.com`).
    3.  Select a profile (e.g., `Fast Dir Bust`).
    4.  Decide whether to run in the background.

#### Ffuf (Web Fuzzing)
Fuzzing for parameters, headers, and endpoints.
*   **Configuration:** Specify target URL with a `FUZZ` keyword, choose profiles (e.g., common params), and provide wordlists.
*   **Usage Examples (Interactive):**
    1.  Select `Web Arsenal` -> `Web Fuzzing - Ffuf`.
    2.  Enter Target URL with FUZZ marker (e.g., `http://example.com/api/FUZZ`).
    3.  Select a profile.
    4.  Decide whether to run in the background.

### 5.3. Exploitation Hub

A centralized module for exploit search and active exploitation.

#### Searchsploit (Exploit Search)
Search the Exploit-DB database for known vulnerabilities and exploits.
*   **Configuration:** Enter a search query (e.g., "nginx 1.14").
*   **Usage Examples (Interactive):**
    1.  Select `Exploitation Hub` -> `Exploit Search - Searchsploit`.
    2.  Enter your search query.
    3.  Decide whether to run in the background.

#### Active Exploitation (SQLMap, Curl, Hydra)
Execute active attacks against identified vulnerabilities or for credential access.

##### SQLMap
Automated SQL injection and database takeover tool.
*   **Configuration:** Specify the target URL (often with vulnerable parameters).
*   **Usage Examples (Interactive):**
    1.  Select `Exploitation Hub` -> `Active Exploitation` -> `SQLMap`.
    2.  Enter the Target URL (e.g., `http://example.com/vulnerable.php?id=1`).
    3.  Decide whether to run in the background.

##### Curl Request Builder
An interactive interface to craft sophisticated HTTP requests with `curl`.
*   **Configuration:** A menu-driven builder allows you to set HTTP method, add custom headers, set request body, manage cookies, and configure output options (verbose, follow redirects). You can preview the `curl` command before execution.
*   **Usage Examples (Interactive):**
    1.  Select `Exploitation Hub` -> `Active Exploitation` -> `Curl`.
    2.  Enter the target URL.
    3.  Use the interactive menu to build your request (e.g., set method to POST, add a JSON body, set custom headers).
    4.  Preview the command.
    5.  Choose to execute.
    6.  Decide whether to run in the background.

##### Hydra
Fast network logon cracker supporting numerous protocols.
*   **Configuration:** Similar to a brute-force module, specify target, service, usernames, and wordlists.
*   **Usage Examples (Interactive):**
    1.  Select `Exploitation Hub` -> `Active Exploitation` -> `Hydra`.
    2.  Follow the prompts for target, service, credentials, etc.
    3.  Decide whether to run in the background.

### 5.4. Network Operations (Sniffer, Poison)

Tools for network traffic analysis and man-in-the-middle attacks.

#### Packet Sniffer (Tcpdump)
Capture and analyze network packets.
*   **Configuration:** Select network interface, capture duration, and filtering options (e.g., host, port, protocol).
*   **Usage Examples (Interactive):**
    1.  Select `Network Operations` -> `Packet Sniffer - Tcpdump`.
    2.  Select an interface (e.g., `eth0`).
    3.  Choose a profile (e.g., `ICMP Only`).
    4.  Decide whether to run in the background.

#### LAN Poisoning (Responder)
Perform LLMNR, NBT-NS, and mDNS poisoning attacks.
*   **Configuration:** Specify the network interface to listen on.
*   **Usage Examples (Interactive):**
    1.  Select `Network Operations` -> `LAN Poisoning - Responder`.
    2.  Enter the network interface (e.g., `eth0`).
    3.  Decide whether to run in the background.

### 5.5. Wireless & RF (WiFi, Bluetooth)

Tools for auditing wireless networks and Bluetooth devices.

#### WiFi Audit (Wifite)
Automated wireless auditing tool.
*   **Configuration:** Specify the wireless interface (must be in monitor mode).
*   **Usage Examples (Interactive):**
    1.  Select `Wireless & RF` -> `WiFi Audit - Wifite`.
    2.  Enter the wireless interface (e.g., `wlan0mon`).
    3.  Decide whether to run in the background.

#### Bluetooth Arsenal
Scan for and interact with Bluetooth devices.
*   **Configuration:** Option to specify a target MAC address or perform a general scan.
*   **Usage Examples (Interactive):**
    1.  Select `Wireless & RF` -> `Bluetooth Arsenal`.
    2.  Enter a target MAC address (optional).
    3.  Choose a profile (e.g., `Scan for Devices`).
    4.  Decide whether to run in the background.

## 6. Dashboard (Results & History)

The Dashboard is your central hub for monitoring active jobs and reviewing past scan results.

1.  **Accessing the Dashboard:** Select `Dashboard (Results & History)` from the main menu.
2.  **Unified View:** The dashboard lists both currently running background jobs and saved scan results from the `scans/` directory.
    *   **ID:** Unique identifier for the job/scan.
    *   **TIMESTAMP:** When the job started or the scan was saved.
    *   **TOOL:** The tool that generated the result (e.g., Nmap, WebEnum, Fuzzer).
    *   **TARGET:** The target of the operation.
    *   **STATUS:** Indicates `RUNNING` (for active jobs), `COMPLETED`, `FAILED`, or `SAVED` (for historical file-based results).
3.  **Viewing Details:** Type the `ID` of any item and press Enter to view its full output or parsed report.
4.  **Navigation:**
    *   `R`: Refresh the list.
    *   `0`: Return to the main menu.

## 7. Troubleshooting & Tips

*   **"Sudo authentication failed" errors:** If Nmap (or other tools requiring root) fails with this message, PURPL will now display the raw error output from `sudo`. This could indicate:
    *   Incorrect password.
    *   User is not in the `sudoers` file.
    *   `sudo` is not installed or configured correctly.
*   **Missing Tools:** If PURPL reports that a tool (e.g., `sqlmap`, `ffuf`) is not found, ensure it's installed on your system and available in your `PATH`.
*   **Proxychains Issues:** Verify `proxychains` is installed and its configuration file (`/etc/proxychains.conf` or `~/.proxychains/proxychains.conf`) is correctly set up.
*   **Networking:** Ensure your network interfaces are up and configured correctly, especially for sniffing and wireless auditing tools.
*   **"Invalid selection" in menus:** Always enter the numeric or alphanumeric key exactly as displayed next to the menu option.
*   **"Press Enter to return to menu..."**: Foreground tasks will pause with this prompt, allowing you to review output before returning to the menu.
*   **Background Jobs:** Remember that background job output is captured and can be viewed via the Dashboard.
*   **File Structure:** Explore the `scans/` directory to directly access raw output files and reports generated by PURPL.
