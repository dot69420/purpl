use std::path::Path;
use std::fs;
use chrono::Local;
use colored::*; 
use crate::history::{append_history, HistoryEntry};
use crate::executor::CommandExecutor;
use crate::io_handler::IoHandler;

pub fn run_fuzzer(target: &str, global_wordlist: Option<&str>, extra_args: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // 1. Validation
    if !target.starts_with("http://") && !target.starts_with("https://") {
        io.println(&format!("{}", "[!] Target must start with http:// or https://".red()));
        return;
    }
    if !target.contains("FUZZ") {
        io.println(&format!("{}", "[!] Target URL must contain the keyword 'FUZZ' where payload should be injected.".yellow()));
        io.println("    Example: http://example.com/FUZZ or http://example.com/api/user?id=FUZZ");
        return;
    }

    // Check ffuf availability
    if executor.execute_output("ffuf", &["-V"]).is_err() {
        io.println(&format!("{}", "[-] 'ffuf' not found. Please install it (go install github.com/ffuf/ffuf/v2@latest).".red()));
        return;
    }

    // 2. Resolve Wordlist
    let wordlist = if let Some(path) = global_wordlist {
        if Path::new(path).exists() {
            path.to_string()
        } else {
            io.println(&format!("{}", format!("[!] Custom wordlist '{}' not found.", path).red()));
            return;
        }
    } else {
        // Default Wordlists
        let candidates = [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt", // Good generic fuzzer
            "wordlists/common.txt"
        ];
        
        let found = candidates.iter().find(|p| Path::new(p).exists());
        match found {
            Some(p) => p.to_string(),
            None => {
                io.print(&format!("{}", "Enter path to wordlist: ".yellow()));
                io.flush();
                let path = io.read_line();
                let path = path.trim();
                if Path::new(path).exists() {
                    path.to_string()
                } else {
                    io.println(&format!("{}", "[!] Wordlist not found.".red()));
                    return;
                }
            }
        }
    };

    // 3. Setup Output
    // Sanitize target for folder name (remove protocol and FUZZ)
    let safe_target = target
        .replace("://", "_")
        .replace('/', "_")
        .replace("FUZZ", "X");
        
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/web/fuzz_{}/{}", safe_target, date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    let output_file = format!("{}/ffuf.json", output_dir);

    io.println(&format!("{}", format!("\n[+] Starting Ffuf on {}", target).green()));
    io.println(&format!("    Wordlist: {}", wordlist));
    io.println(&format!("[+] Saving output to: {}", output_file));

    // 4. Build Command
    // ffuf -u URL -w WORDLIST -o OUTPUT -of json
    let mut args = vec![
        "-u".to_string(), target.to_string(),
        "-w".to_string(), wordlist,
        "-o".to_string(), output_file.clone(),
        "-of".to_string(), "json".to_string(),
        "-c".to_string(), // Colorize
    ];

    if let Some(extras) = extra_args {
         for arg in extras.split_whitespace() {
             args.push(arg.to_string());
         }
    }

    let mut cmd_bin = "ffuf".to_string();

    if use_proxy {
        args.insert(0, cmd_bin);
        cmd_bin = "proxychains".to_string();
    }

    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    // 5. Execute
    let status = executor.execute(&cmd_bin, &args_str);

    match status {
        Ok(s) => {
            if s.success() {
                io.println(&format!("{}", "\n[+] Fuzzing complete.".green()));
                let _ = append_history(&HistoryEntry::new("WebFuzz", target, "Success"));
            } else {
                io.println(&format!("{}", "\n[!] Ffuf failed or was interrupted.".yellow()));
                let _ = append_history(&HistoryEntry::new("WebFuzz", target, "Failed/Stopped"));
            }
        },
        Err(e) => io.println(&format!("{} {}", "[!] Failed to start process:".red(), e)),
    }
}