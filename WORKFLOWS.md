# PURPL Module Workflows

This document outlines the standard workflows for each module within the **purpl** (formerly `nt_test`) CLI.

## Global Features
**Smart Input & Persistence:**
The application remembers the last target (IP/URL) entered across all modules.
- When prompted for a target (e.g., `Enter target IP [10.10.10.10]: `), simply press **Enter** to reuse the last value.
- This allows seamless transitions between modules (e.g., Nmap -> Web Enumeration) without re-typing the address.

---

## 1. Network Recon (Nmap & Discovery)
Performs network reconnaissance and port scanning via a structured submenu.

### Workflow
1.  Select **Network Recon** from the main menu.
2.  Select **Nmap Automator** from the submenu.
3.  **Target Entry:** Enter the Target IP or Hostname (or press Enter to use the cached target).
4.  **Profile Selection:**
    *   The tool offers various scan profiles (Stealth, Connect, Intense, etc.).
    *   Press **Enter** to select the default profile (**Stealth & Vuln**).
    *   Or enter a number to choose a specific profile.
5.  **Execution:**
    *   **Host Discovery:** Checks if the host is up.
    *   **Deep Scan:** Enumerates ports, versions, and scripts based on the profile.
6.  Results are saved to `scans/nmap/<target_ip>/<date>/`.

---

## 2. Exploit Search (Searchsploit)
**Status:** *Improved*

The Exploit Search module allows you to find known vulnerabilities for specific services or software versions using the Exploit-DB archive.

### Workflow
There are two ways to use this module:

#### A. Direct Search (Interactive)
1.  Select **Exploit Search** from the main menu (under Exploitation Hub).
2.  When prompted `Enter Search Query or Target IP/XML:`, type your search terms directly.
    *   *Example:* `apache 2.4`
    *   *Example:* `windows smb`
3.  The tool will execute `searchsploit` with your query and display the top 20 results in a formatted table.
4.  After viewing results, you will be prompted: `Search again? (Enter new query, 'q' to quit)`.
    *   You can refine your search or start a new one without returning to the main menu.
    *   Enter `q` or `exit` to return to the main menu.

#### B. Auto-Correlation (from Nmap Scan)
1.  Perform an **Nmap Scan** on a target first.
2.  Select **Exploit Search** from the main menu.
3.  When prompted, enter the **Target IP** of the previously scanned host.
    *   *Example:* `10.10.10.10`
4.  The tool will automatically:
    *   Locate the Nmap XML report for that target.
    *   Parse all open ports and service versions.
    *   Query Exploit-DB for each specific service found.
    *   Display relevant exploits for each service.
5.  After the auto-scan completes, you will be dropped into the interactive search loop, allowing you to manually search for any specific findings or new queries.

---

## 3. Web Enumeration (Gobuster)
Brute-forces hidden directories and files on a web server.

### Workflow
1.  Select **Web Arsenal** -> **Web Enumeration**.
2.  Enter the **Target URL** (must include `http://` or `https://`).
    *   *Smart Input:* Press Enter to use the last target.
3.  The tool runs `gobuster` using a default wordlist (typically `common.txt` or similar).
4.  Found paths are displayed and saved to `scans/web/<target>/`.

---

## 4. Web Fuzzing (Ffuf)
Fuzzes specific parameters or endpoints.

### Workflow
1.  Select **Web Arsenal** -> **Web Fuzzing**.
2.  Enter the **Target URL** including the `FUZZ` keyword where you want to inject payloads.
    *   *Example:* `http://site.com/FUZZ` (Directory fuzzing)
    *   *Example:* `http://site.com/api.php?id=FUZZ` (Parameter fuzzing)
3.  The tool executes `ffuf` and filters for valid responses (e.g., status 200).

---

## 5. Active Exploitation
Launches active attacks using tools like SQLMap or Curl.

### Workflow
1.  Select **Exploitation Hub** -> **Active Exploitation**.
2.  **Target Selection:**
    *   Enter the target URL/IP (or use Smart Input).
3.  **Tool Selection:**
    *   Choose the sub-tool if prompted (or specify via `--tool` in CLI):
        *   **SQLMap:** For SQL injection testing.
        *   **Curl:** For sophisticated manual request building/testing.
        *   **Hydra:** For credential brute-forcing (see below).
4.  **Execution:** The tool executes the attack, utilizing proxychains if enabled, and logs output to `scans/exploit/<tool>/<target>/`.

### Hydra (Credential Access) Sub-Module
If **Hydra** is selected within Exploitation:
1.  **Service Auto-Detection:**
    *   The tool automatically detects open ports/services from the target's Nmap scan.
    *   Select a detected service (e.g., `ssh (22/tcp)`) to auto-configure.
2.  **Profile Selection:**
    *   **Quick Spray:** Top usernames vs Top passwords.
    *   **Single User:** Brute-force a specific user.
    *   **Custom:** Provide your own wordlists.
3.  **Execution:** Runs `hydra` and saves results to `scans/brute/<target>/`.

---

## 6. LAN Poisoning (Responder)
Performs LLMNR/NBT-NS poisoning to capture NTLM hashes.

### Workflow
1.  Select **Network Operations** -> **LAN Poisoning**.
2.  Enter the **Network Interface** to listen on (e.g., `eth0`, `wlan0`).
3.  The tool starts `responder` in analysis or active mode (requires Root).
4.  Captured hashes are logged to the `scans` directory.

---

## 8. WiFi Audit (Wifite)
Automated wireless network auditing.

### Workflow
1.  Select **Wireless & RF** -> **WiFi Audit**.
2.  Enter the **Wireless Interface** (e.g., `wlan0mon`).
3.  The tool starts `wifite` to scan for networks and attempt attacks (WEP, WPA Handshake capture, WPS).
4.  *Note:* Requires a monitor-mode capable wireless card.

---

## 9. Packet Sniffer (Tcpdump)
Captures network traffic for analysis, with an interactive configuration wizard.

### Workflow
1.  Select **Network Operations** -> **Packet Sniffer**.
2.  **Interface Selection:**
    *   The tool lists available network interfaces (via `ip link`).
    *   Select an interface from the list (e.g., `eth0`, `wlan0`) or enter one manually.
3.  **Filter Selection:**
    *   **All Traffic:** Capture everything.
    *   **HTTP/FTP/Telnet:** Focus on unencrypted credentials.
    *   **DNS:** Monitor domain lookups.
    *   **ICMP:** Monitor ping traffic.
    *   **Custom:** Enter a custom BPF filter (e.g., `host 1.2.3.4 and port 80`).
4.  **Mode Selection:**
    *   **Passive Capture:** Saves packets to a `.pcap` file in `scans/packets/` for later analysis (e.g., with Wireshark).
    *   **Live Analysis:** Parses traffic in real-time and prints a summary to the screen (Source, Dest, Protocol, Payload Preview).

---

## 10. Bluetooth Arsenal
Scans and attacks Bluetooth devices.

### Workflow
1.  Select **Wireless & RF** -> **Bluetooth Arsenal**.
2.  Enter a **Target MAC** address OR type `scan` to discover devices.
3.  If `scan` is selected, it runs `hcitool scan` and `hcitool lescan`.
4.  If a MAC is provided, it attempts to browse services (`sdptool`) and ping flood (`l2ping`) the device.

---

## 11. Results Viewer
Interactive browser for all scan data.

### Workflow
1.  Select **Results Viewer** from the main menu.
2.  **Select Category:** Choose the tool type (e.g., `NMAP`, `WEB`, `WIFI`).
3.  **Select Target:** Choose the target identifier (IP/URL).
4.  **Select Date:** Choose the specific scan timestamp.
5.  **View Report:** The tool parses and displays the results (e.g., parsed Nmap services, cracked WiFi keys) directly in the terminal.

