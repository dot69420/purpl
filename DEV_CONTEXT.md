# NT_TEST Development Context & Architecture Blueprint

## 1. Project Philosophy
`nt_test` is a Rust-based CLI wrapper for offensive security tools. It prioritizes:
- **Safety:** Sudo validation, input sanitization.
- **Usability:** Profile-based execution (no manual flag memorization).
- **Persistence:** Structured output (`scans/<type>/<date>/`).
- **Unified Reporting:** One command to view all results.

## 2. Architecture Patterns
To avoid "slop code", all new modules **MUST** adhere to this pattern:

### A. Module Structure (`src/<module>.rs`)
1.  **Profiles Enum/Struct:** Define presets (e.g., `Fast`, `Thorough`).
2.  **Execution Function:** `pub fn run_<module>(target: &str, use_proxy: bool)`.
3.  **Output Management:**
    - Generate timestamped directory: `scans/<module_name>/<date>/`.
    - Always capture `stdout`/`stderr` to a raw file (e.g., `raw_output.txt`).
    - Parse output in real-time or post-execution for the Unified Report.

### B. Integration (`src/main.rs`)
1.  **CLI Arg:** Add `#[arg(long)]` for the new module.
2.  **Menu:** Add entry to `tools` vector in interactive loop.
3.  **Dispatch:** Call the module's run function.

### C. Reporting (`src/report.rs`)
1.  **Detection:** Update `display_scan_report` to check for the new module's output file.
2.  **Parsing:** Implement a specific parser (e.g., `parse_gobuster_output`).

---

## 3. Roadmap & Specifications

### Phase 1: Web Enumeration (`src/web.rs`)
- **Tool:** `gobuster`.
- **Logic:**
    - Input: URL (validate http/https).
    - Wordlists: Check `/usr/share/wordlists/` (Kali standard). Fallback to user input if missing.
    - Profiles:
        - `Quick`: `/usr/share/wordlists/dirb/common.txt` or similar.
        - `Full`: `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`.
- **Output:** `scans/web/<date>/gobuster.txt`.

### Phase 2: Credential Access (`src/brute.rs`)
- **Tool:** `hydra`.
- **Logic:**
    - Context: Should ideally link to Nmap results to see open ports (22, 21, 3389).
    - Input: Target IP, Protocol, User List, Pass List.
- **Output:** `scans/brute/<date>/hydra.json` (if possible) or text.

### Phase 3: Exploit Search (`src/exploit.rs`)
- **Tool:** `searchsploit` (Exploit-DB).
- **Logic:**
    - Input: `nmap` XML output path.
    - Parsing: Extract `<service product="..." version="...">`.
    - Action: `searchsploit --json "product version"`.
- **Output:** Display table of matching exploits in terminal.

### Phase 4: LAN Poisoning (`src/poison.rs`)
- **Tool:** `responder`.
- **Logic:**
    - Root Required: Yes.
    - Interface: Select via `ip link`.
    - Profiles: `Analyze` (-A), `Attack` (-I).
- **Output:** Parse `Responder-Session.log` for captured hashes (NTLMv2).

## 4. Coding Standards
- **Error Handling:** Use `match` or `if let`. Avoid `unwrap()` on external inputs.
- **Dependencies:** Keep lightweight. Use `std::process::Command`.
- **UI:** Use `colored` and `indicatif` for consistent look & feel.
