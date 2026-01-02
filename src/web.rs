use std::process::{Command, Stdio};
use std::io::{self, Write};
use std::path::Path;
use std::fs;
use chrono::Local;
use colored::*;
use crate::history::{append_history, HistoryEntry};

#[derive(Debug, Clone)]
struct WebProfile {
    name: String,
    description: String,
    wordlist: String,
    flags: Vec<&'static str>,
}

impl WebProfile {
    fn new(name: &str, description: &str, wordlist: &str, flags: &[&'static str]) -> Self {
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

pub fn run_web_enum(target: &str, use_proxy: bool) {
    // 1. Validation
    if !target.starts_with("http://") && !target.starts_with("https://") {
        println!("{}", "[!] Target must start with http:// or https://".red());
        return;
    }

    // Check gobuster availability
    if Command::new("gobuster").arg("version").output().is_err() {
        println!("{}", "[-] 'gobuster' not found. Please install it (sudo pacman -S gobuster).".red());
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
    println!("\n{}", "Select Web Enumeration Profile:".blue().bold());
    for (i, p) in profiles.iter().enumerate() {
        println!("[{}] {} - {}", i + 1, p.name.green(), p.description);
    }

    print!("\nChoose a profile [1-{}]: ", profiles.len());
    let _ = io::stdout().flush();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();

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
        print!("{}", "Enter path to wordlist: ".yellow());
        let _ = io::stdout().flush();
        let mut path = String::new();
        io::stdin().read_line(&mut path).unwrap_or_default();
        let path = path.trim();
        if Path::new(path).exists() {
            selected_profile.wordlist = path.to_string();
        } else {
            println!("{}", "[!] Wordlist not found.".red());
            return;
        }
    }

    // 5. Setup Output
    let safe_target = target.replace("://", "_").replace('/', "_");
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/web/{}/{}", safe_target, date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    let output_file = format!("{}/gobuster.txt", output_dir);

    println!("{}", format!("\n[+] Starting Gobuster on {}", target).green());
    println!("    Wordlist: {}", selected_profile.wordlist);
    println!("[+] Saving output to: {}", output_file);

    // 6. Execute
    // cmd: gobuster dir -u <url> -w <wordlist> [flags]
    let mut cmd_args = vec!["dir", "-u", target, "-w", &selected_profile.wordlist, "-o", &output_file];
    cmd_args.extend(selected_profile.flags.iter());

    let mut final_cmd = "gobuster";
    let mut final_args_vec: Vec<String> = cmd_args.iter().map(|s| s.to_string()).collect();

    if use_proxy {
        final_args_vec.insert(0, "gobuster".to_string());
        final_cmd = "proxychains";
    }

    let final_args_str: Vec<&str> = final_args_vec.iter().map(|s| s.as_str()).collect();

    let status = Command::new(final_cmd)
        .args(&final_args_str)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();

    match status {
        Ok(s) => {
            if s.success() {
                println!("{}", "\n[+] Enumeration complete.".green());
                let _ = append_history(&HistoryEntry::new("WebEnum", target, "Success"));
            } else {
                println!("{}", "\n[!] Gobuster failed or was interrupted.".yellow());
                let _ = append_history(&HistoryEntry::new("WebEnum", target, "Failed/Stopped"));
            }
        },
        Err(e) => println!("{} {}", "[!] Failed to start process:".red(), e),
    }
}
