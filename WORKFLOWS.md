# PURPL Module Workflows

This document outlines the standard workflows for each module within the **purpl** CLI. 
All modules now follow the **"Always a Job"** pattern, allowing execution in the foreground (blocking with live output) or background (non-blocking).

## 1. Exploit Search (Searchsploit)
**Status:** *Refactored for Background Jobs*

The Exploit Search module allows you to find known vulnerabilities for specific services or software versions using the Exploit-DB archive.

### Workflow
1.  **Configuration:**
    *   Prompt: `Enter Search Query or Target IP/XML`.
    *   *Input:* Search terms (e.g., `apache 2.4`) or Target IP (for auto-correlation).
2.  **Execution Mode:**
    *   Prompt: `Run search in background? (y/N)`.
    *   *Foreground:* Displays results in a table interactively.
    *   *Background:* Runs headless, output viewable via "View Background Jobs".

---

## 2. Network Scan (Nmap)
Performs network reconnaissance and port scanning.

### Workflow
1.  **Configuration:**
    *   Select **Network Scan**.
    *   Enter **Target IP**.
    *   Select **Scan Profile** (Stealth, Connect, Quick, etc.).
2.  **Execution Mode:**
    *   Prompt: `Run scan in background? (y/N)`.
    *   *Foreground:* Shows live Nmap output.
    *   *Background:* Runs detached.
3.  **Results:** Saved to `scans/nmap/<target>/`.

---

## 3. Web Enumeration (Gobuster)
Brute-forces hidden directories and files.

### Workflow
1.  **Configuration:**
    *   Select **Web Enumeration**.
    *   Enter **Target URL**.
    *   Select **Profile** (Quick, Deep, Manual).
2.  **Execution Mode:**
    *   Prompt: `Run scan in background? (y/N)`.
3.  **Results:** Saved to `scans/web/<target>/`.

---

## 4. Web Fuzzing (Ffuf)
Fuzzes parameters or endpoints.

### Workflow
1.  **Configuration:**
    *   Select **Web Fuzzing**.
    *   Enter **Target URL** (with `FUZZ` keyword).
    *   Select **Wordlist**.
2.  **Execution Mode:**
    *   Prompt: `Run fuzzing in background? (y/N)`.
3.  **Results:** Saved to `scans/web/fuzz_<target>/`.

---

## 5. Active Exploitation
Launches active attacks (SQLMap, Curl, Hydra).

### Workflow
1.  **Configuration:**
    *   Select **Exploitation**.
    *   Select **Target** (Existing or New).
    *   Select **Tool** (SQLMap, Curl, Hydra).
    *   Configure specific tool parameters (Methods, Headers, Payloads).
2.  **Execution Mode:**
    *   Prompt: `Run exploitation in background? (y/N)`.
3.  **Results:** Saved to `scans/exploit/<tool>/<target>/`.

---

## 6. LAN Poisoning (Responder)
LLMNR/NBT-NS poisoning.

### Workflow
1.  **Configuration:**
    *   Select **LAN Poisoning**.
    *   Select **Interface**.
    *   Select **Profile** (Analyze, Basic, Aggressive).
2.  **Execution Mode:**
    *   Prompt: `Run poisoning in background? (y/N)`.
3.  **Results:** Saved to `scans/poison/`.

---

## 7. WiFi Audit (Wifite)
Automated wireless auditing.

### Workflow
1.  **Configuration:**
    *   Select **WiFi Audit**.
    *   Enter **Interface**.
    *   Select **Profile** (Auto-Pwn, WPS, WPA, etc.).
2.  **Execution Mode:**
    *   Prompt: `Run WiFi audit in background? (y/N)`.
3.  **Results:** Saved to `scans/wifi/`.

---

## 8. Packet Sniffer (Tcpdump)
Captures network traffic.

### Workflow
1.  **Configuration:**
    *   Select **Packet Sniffer**.
    *   Select **Interface**.
    *   Select **Filter Profile** (All, HTTP, DNS, Custom).
    *   Select **Mode** (Capture/Live).
2.  **Execution Mode:**
    *   Prompt: `Run sniffer in background? (y/N)`.
3.  **Results:** Saved to `scans/packets/`.

---

## 9. Bluetooth Arsenal
Bluetooth scanning and attacks.

### Workflow
1.  **Configuration:**
    *   Select **Bluetooth Arsenal**.
    *   Select **Profile** (Scan, Info, Flood).
    *   Enter **Target MAC** (if required).
2.  **Execution Mode:**
    *   Prompt: `Run bluetooth attack in background? (y/N)`.
3.  **Results:** Saved to `scans/bluetooth/`.