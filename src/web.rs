use std::io::Write;
use std::path::Path;
use std::fs;
use chrono::Local;
use colored::*;
use crate::history::{append_history, HistoryEntry};
use crate::executor::CommandExecutor;
use crate::io_handler::IoHandler;

#[derive(Debug, Clone)]
pub struct WebProfile {
    pub name: String,
    pub description: String,
    pub wordlist: String,
    pub flags: Vec<&'static str>,
}

impl WebProfile {
    pub fn new(name: &str, description: &str, wordlist: &str, flags: &[&'static str]) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            wordlist: wordlist.to_string(),
            flags: flags.to_vec(),
        }
    }
}

// Helper to find valid wordlist
fn find_wordlist(candidates: &[&str]) -> Option<String> {
    for path in candidates {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

pub fn run_web_enum(target: &str, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // 1. Validation
    if !target.starts_with("http://") && !target.starts_with("https://") {
        io.println(&format!("{}", "[!] Target must start with http:// or https://".red()));
        return;
    }

    // Check gobuster availability
    if executor.execute_output("gobuster", &["version"]).is_err() {
        io.println(&format!("{}", "[-] 'gobuster' not found. Please install it (sudo pacman -S gobuster).".red()));
        return;
    }

    // 2. Resolve Wordlists
    let common_list = find_wordlist(&[
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "wordlists/common.txt" // Local fallback
    ]).unwrap_or_else(|| "manual".to_string());

    let medium_list = find_wordlist(&[
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "wordlists/medium.txt"
    ]).unwrap_or_else(|| "manual".to_string());

    // 3. Define Profiles
    let mut profiles = Vec::new();
    
    // Quick Profile
    if common_list != "manual" {
        profiles.push(WebProfile::new(
            "Quick Scan",
            "Scans for common files and directories (common.txt).",
            &common_list,
            &["-t", "50", "--no-error"]
        ));
    }

    // Full Profile
    if medium_list != "manual" {
        profiles.push(WebProfile::new(
            "Deep Scan",
            "Large wordlist, slower but thorough.",
            &medium_list,
            &["-t", "40", "--no-error", "-x", "php,html,txt"]
        ));
    }

    // Manual Profile (Always available)
    profiles.push(WebProfile::new(
        "Manual/Custom",
        "Select your own wordlist.",
        "manual",
        &["-t", "50"]
    ));

    // 4. Select Profile
    io.println(&format!("\n{}", "Select Web Enumeration Profile:".blue().bold()));
    for (i, p) in profiles.iter().enumerate() {
        io.println(&format!("[{}] {} - {}", i + 1, p.name.green(), p.description));
    }

    io.print(&format!("\nChoose a profile [1-{}]: ", profiles.len()));
    io.flush();
    let input = io.read_line();

    let mut selected_profile = if let Ok(idx) = input.trim().parse::<usize>() {
        if idx > 0 && idx <= profiles.len() {
            profiles[idx - 1].clone()
        } else {
            profiles[0].clone()
        }
    } else {
        profiles[0].clone()
    };

    // Handle Manual Wordlist
    if selected_profile.wordlist == "manual" {
        io.print(&format!("{}", "Enter path to wordlist: ".yellow()));
        io.flush();
        let path = io.read_line();
        let path = path.trim();
        if Path::new(path).exists() {
            selected_profile.wordlist = path.to_string();
        } else {
            io.println(&format!("{}", "[!] Wordlist not found.".red()));
            return;
        }
    }

    // 5. Setup Output
    let safe_target = target.replace("://", "_").replace('/', "_");
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/web/{}/{}", safe_target, date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    let output_file = format!("{}/gobuster.txt", output_dir);

    io.println(&format!("{}", format!("\n[+] Starting Gobuster on {}", target).green()));
    io.println(&format!("    Wordlist: {}", selected_profile.wordlist));
    io.println(&format!("[+] Saving output to: {}", output_file));

    // 6. Execute
    let (final_cmd, final_args) = build_gobuster_command("gobuster", target, &selected_profile.wordlist, &output_file, &selected_profile.flags, use_proxy);
    let final_args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();

    let status = executor.execute(&final_cmd, &final_args_str);

    match status {
        Ok(s) => {
            if s.success() {
                io.println(&format!("{}", "\n[+] Enumeration complete.".green()));
                let _ = append_history(&HistoryEntry::new("WebEnum", target, "Success"));
            } else {
                io.println(&format!("{}", "\n[!] Gobuster failed or was interrupted.".yellow()));
                let _ = append_history(&HistoryEntry::new("WebEnum", target, "Failed/Stopped"));
            }
        },
        Err(e) => io.println(&format!("{} {}", "[!] Failed to start process:".red(), e)),
    }
}

pub fn build_gobuster_command(
    base_cmd: &str,
    target: &str,
    wordlist: &str,
    output_file: &str,
    flags: &[&str],
    use_proxy: bool
) -> (String, Vec<String>) {
    let mut args = vec!["dir".to_string(), "-u".to_string(), target.to_string(), "-w".to_string(), wordlist.to_string(), "-o".to_string(), output_file.to_string()];
    args.extend(flags.iter().map(|s| s.to_string()));

    let mut final_cmd = base_cmd.to_string();
    let mut final_args = args;

    if use_proxy {
        final_args.insert(0, final_cmd);
        final_cmd = "proxychains".to_string();
    }

    (final_cmd, final_args)
}

#[cfg(test)]
#[path = "web_tests.rs"]
mod tests;
