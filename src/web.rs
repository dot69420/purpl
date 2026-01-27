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

#[derive(Debug, Clone)]
pub struct WebConfig {
    pub target: String,
    pub profile: WebProfile,
    pub extra_args: Option<String>,
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

pub fn configure_web_enum(target: &str, extra_args: Option<&str>, executor: &dyn CommandExecutor, io: &dyn IoHandler) -> Option<WebConfig> {
    // 1. Validation
    if !target.starts_with("http://") && !target.starts_with("https://") {
        io.println(&format!("{}", "[!] Target must start with http:// or https://".red()));
        return None;
    }

    // Check gobuster availability
    if executor.execute_output("gobuster", &["version"]).is_err() {
        io.println(&format!("{}", "[-] 'gobuster' not found. Please install it (sudo pacman -S gobuster).".red()));
        return None;
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
            return None;
        }
    }

    Some(WebConfig {
        target: target.to_string(),
        profile: selected_profile,
        extra_args: extra_args.map(|s| s.to_string()),
    })
}

pub fn execute_web_enum(config: WebConfig, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // 5. Setup Output
    let safe_target = config.target.replace("://", "_").replace('/', "_");
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/web/{}/{}", safe_target, date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    let output_file = format!("{}/gobuster.txt", output_dir);

    io.println(&format!("{}", format!("\n[+] Starting Gobuster on {}", config.target).green()));
    io.println(&format!("    Wordlist: {}", config.profile.wordlist));
    io.println(&format!("[+] Saving output to: {}", output_file));

    // 6. Execute
    let mut flags_vec: Vec<String> = config.profile.flags.iter().map(|s| s.to_string()).collect();
    if let Some(extras) = &config.extra_args {
         for arg in extras.split_whitespace() {
             flags_vec.push(arg.to_string());
         }
    }
    
    let flags_ref: Vec<&str> = flags_vec.iter().map(|s| s.as_str()).collect();

    let (final_cmd, final_args) = build_gobuster_command("gobuster", &config.target, &config.profile.wordlist, &output_file, &flags_ref, use_proxy);
    let final_args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();

    let status = executor.execute(&final_cmd, &final_args_str);

    match status {
        Ok(s) => {
            if s.success() {
                io.println(&format!("{}", "\n[+] Enumeration complete.".green()));
                let _ = append_history(&HistoryEntry::new("WebEnum", &config.target, "Success"));
            } else {
                io.println(&format!("{}", "\n[!] Gobuster failed or was interrupted.".yellow()));
                let _ = append_history(&HistoryEntry::new("WebEnum", &config.target, "Failed/Stopped"));
            }
        },
        Err(e) => io.println(&format!("{} {}", "[!] Failed to start process:".red(), e)),
    }
}

// Backward compatibility wrapper
pub fn run_web_enum(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    if let Some(config) = configure_web_enum(target, extra_args, executor, io) {
        execute_web_enum(config, use_proxy, executor, io);
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
