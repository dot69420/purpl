# PURPL Development Context & Architecture Blueprint

## 1. Project Philosophy
`purpl` is a Rust-based CLI wrapper for offensive security tools. It prioritizes:
- **Safety:** Sudo validation, input sanitization.
- **Usability:** Profile-based execution (no manual flag memorization).
- **Persistence:** Structured output (`scans/<type>/<date>/`).
- **Unified Reporting:** One command to view all results.
- **Testability:** High code coverage through dependency injection and mocking.

## 2. Architecture Patterns
To ensure reliability and testability, all modules **MUST** adhere to this pattern:

### A. Dependency Injection
All core logic is decoupled from side effects (System commands, IO) via traits defined in `src/executor.rs` and `src/io_handler.rs`.
- **`CommandExecutor`:** Abstracts system command execution (`execute`, `execute_output`, `spawn_stdout`, `is_root`).
- **`IoHandler`:** Abstracts Input/Output operations (`println`, `print`, `read_line`, `read_input`, `flush`).

### B. Module Structure (`src/<module>.rs`)
1.  **Profiles Enum/Struct:** Define presets (e.g., `Fast`, `Thorough`).
2.  **Execution Function:**
    ```rust
    pub fn run_<module>(
        target: &str,
        use_proxy: bool,
        executor: &dyn CommandExecutor,
        io: &dyn IoHandler
    )
    ```
3.  **Input Handling:**
    - Use `io.read_input(prompt, default)` for interactive arguments.
    - Leverage `history::get_last_target()` to provide smart defaults for targets.
4.  **Output Management:**
    - Generate timestamped directory: `scans/<module_name>/<date>/`.
    - Always capture `stdout`/`stderr` or logs.
    - Parse output in real-time or post-execution.

### C. Integration (`src/main.rs`)
1.  **CLI Arg:** Add `#[arg(long)]` for the new module.
2.  **Menu:** Add entry to `tools` vector in `run_interactive_mode` (or appropriate submenu).
3.  **Dispatch:** Call the module's run function using the real executor and io handler.

### D. Reporting (`src/report.rs`)
1.  **Interactive Viewer:** Use `report::view_results(io)` for the main results menu.
2.  **Detection:** Update `display_scan_report` to check for the new module's output file.
3.  **Parsing:** Implement a specific parser (e.g., `parse_gobuster_output`).

---

## 3. Roadmap & Specifications

### Phase 1: Web Enumeration (`src/web.rs`)
- **Tool:** `gobuster`.
- **Logic:**
    - Input: URL (validate http/https).
    - Wordlists: Check `/usr/share/wordlists/`. Fallback to user input.
    - Profiles: `Quick`, `Deep`, `Manual`.
- **Output:** `scans/web/<date>/gobuster.txt`.

### Phase 2: Credential Access (`src/brute.rs`)
- **Tool:** `hydra`.
- **Logic:**
    - Input: Target IP, Protocol, User List, Pass List.
- **Output:** `scans/brute/<date>/hydra.txt`.

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
    - Profiles: `Analyze` (-A), `Basic`, `Aggressive`.
- **Output:** Parse logs/ display output.

### Phase 8: Bluetooth Arsenal (`src/bluetooth.rs`)
- **Tools:** `hciconfig`, `hcitool`, `sdptool`, `l2ping`.
- **Logic:**
    - **Recon:** `hcitool scan` (Classic) and `hcitool lescan` (LE).
    - **Enum:** `sdptool browse <MAC>`.
    - **Stress:** `l2ping -f <MAC>`.
    - **Hardware:** Auto-detect `hci0`.
- **Output:** `scans/bluetooth/<date>/scan.txt`.

## 4. Coding Standards
- **Error Handling:** Use `match` or `if let`. Avoid `unwrap()` on external inputs.
- **Dependencies:** Use `CommandExecutor` trait for ANY system call. Use `IoHandler` for ANY printing/reading.
- **Testing:**
    - Write unit tests for every module in `src/<module>_tests.rs`.
    - Use `MockExecutor` and `MockIoHandler` to simulate environment.
    - Ensure >80% coverage.
- **UI:** Use `colored` via `io.println` for consistent look & feel.
