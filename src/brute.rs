use std::io::Write;
use std::path::Path;
use std::fs;
use chrono::Local;
use colored::*;
use crate::history::{append_history, HistoryEntry};
use crate::executor::CommandExecutor;
use crate::io_handler::IoHandler;

#[derive(Debug, Clone)]
pub struct BruteProfile {
    pub name: String,
    pub description: String,
    pub userlist: String,
    pub passlist: String,
    pub flags: Vec<&'static str>,
}

impl BruteProfile {
    pub fn new(name: &str, description: &str, userlist: &str, passlist: &str, flags: &[&'static str]) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            userlist: userlist.to_string(),
            passlist: passlist.to_string(),
            flags: flags.to_vec(),
        }
    }
}

// Reuse helper to find valid wordlist (similar to web.rs)
fn find_wordlist(candidates: &[&str]) -> Option<String> {
    for path in candidates {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

pub fn run_brute_force(target: &str, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // 1. Validation
    if executor.execute_output("hydra", &["-h"]).is_err() {
        io.println(&format!("{}", "[-] 'hydra' not found. Please install it (sudo pacman -S hydra).".red()));
        return;
    }

    if target.trim().is_empty() {
        io.println(&format!("{}", "[!] Target cannot be empty.".red()));
        return;
    }

    // 2. Select Protocol
    io.println(&format!("\n{}", "Select Target Protocol:".blue().bold()));
    let protocols = vec!["ssh", "ftp", "telnet", "rdp", "mysql", "postgresql"];
    for (i, p) in protocols.iter().enumerate() {
        io.println(&format!("[{}] {}", i + 1, p));
    }
    
    io.print(&format!("\nChoose protocol [1-{}]: ", protocols.len()));
    io.flush();
    let p_in = io.read_line();
    
    let protocol = if let Ok(idx) = p_in.trim().parse::<usize>() {
        if idx > 0 && idx <= protocols.len() {
            protocols[idx - 1]
        } else {
            "ssh"
        }
    } else {
        "ssh"
    };

    // 3. Resolve Wordlists
    // Common Usernames
    let user_list_path = find_wordlist(&[
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/metasploit/unix_users.txt",
        "wordlists/users.txt"
    ]).unwrap_or_else(|| "manual".to_string());

    // Common Passwords
    let pass_list_path = find_wordlist(&[
        "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
        "/usr/share/wordlists/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt", // Good for quick spray
        "/usr/share/wordlists/metasploit/unix_passwords.txt", 
        "wordlists/passwords.txt"
    ]).unwrap_or_else(|| "manual".to_string());

    // 4. Define Profiles
    let mut profiles = Vec::new();

    if user_list_path != "manual" && pass_list_path != "manual" {
        profiles.push(BruteProfile::new(
            "Quick Spray",
            "Top usernames vs Top passwords. Fast check for weak creds.",
            &user_list_path,
            &pass_list_path,
            &["-t", "-I"] // -I to ignore existing restore file
        ));
    }

    profiles.push(BruteProfile::new(
        "Single User / Spray",
        "Target one specific user (e.g., 'root') with a password list.",
        "input", // placeholder
        &pass_list_path,
        &["-t", "4"]
    ));

    profiles.push(BruteProfile::new(
        "Custom / Manual",
        "Select your own lists.",
        "manual",
        "manual",
        &["-t", "4"]
    ));

    // 5. Select Profile
    io.println(&format!("\n{}", "Select Attack Profile:".blue().bold()));
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

    // Handle Input/Manual
    let user_arg;
    if selected_profile.name.contains("Single User") {
        io.print(&format!("{}", "Enter Username to target: ".yellow()));
        io.flush();
        let user = io.read_line();
        selected_profile.userlist = user.trim().to_string();
        user_arg = "-l".to_string(); // Little l for single user
    } else if selected_profile.userlist == "manual" {
         io.print(&format!("{}", "Enter path to USER list: ".yellow()));
         io.flush();
         let path = io.read_line();
         selected_profile.userlist = path.trim().to_string();
         user_arg = "-L".to_string(); // Big L for list
    } else {
        user_arg = "-L".to_string();
    }

    if selected_profile.passlist == "manual" {
         io.print(&format!("{}", "Enter path to PASSWORD list: ".yellow()));
         io.flush();
         let path = io.read_line();
         selected_profile.passlist = path.trim().to_string();
    }
    let pass_arg = "-P".to_string(); // Big P for list (usually) - wait, hydra uses -P for list, -p for single

    // 6. Setup Output
    let safe_target = target.replace("://", "_").replace('/', "_");
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/brute/{}/{}", safe_target, date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    let output_file = format!("{}/hydra.txt", output_dir);

    io.println(&format!("{}", format!("\n[+] Starting Hydra on {}://{}", protocol, target).green()));
    io.println(&format!("[+] Saving output to: {}", output_file));

    // 7. Execute
    let (final_cmd, final_args) = build_hydra_command(
        "hydra",
        &selected_profile.flags,
        &user_arg,
        &selected_profile.userlist,
        &pass_arg,
        &selected_profile.passlist,
        &output_file,
        target,
        protocol,
        use_proxy
    );
    let final_args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();

    // Hydra outputs to stderr largely for status, stdout for found
    let status = executor.execute(&final_cmd, &final_args_str);

    match status {
        Ok(s) => {
            if s.success() {
                // Check if output file has content (successes)
                if let Ok(content) = fs::read_to_string(&output_file) {
                    if !content.trim().is_empty() {
                         io.println(&format!("{}", "\n[+] Credentials Found!".green().bold()));
                         io.println(&content);
                         let _ = append_history(&HistoryEntry::new("BruteForce", target, "CRACKED"));
                    } else {
                         io.println(&format!("{}", "\n[-] No credentials found.".yellow()));
                         let _ = append_history(&HistoryEntry::new("BruteForce", target, "Failed"));
                    }
                }
            } else {
                io.println(&format!("{}", "\n[!] Hydra failed or was interrupted.".yellow()));
            }
        },
        Err(e) => io.println(&format!("{} {}", "[!] Failed to start process:".red(), e)),
    }
}

pub fn build_hydra_command(
    base_cmd: &str,
    flags: &[&str],
    user_arg: &str,
    userlist: &str,
    pass_arg: &str,
    passlist: &str,
    output_file: &str,
    target: &str,
    protocol: &str,
    use_proxy: bool
) -> (String, Vec<String>) {
    let mut cmd_args: Vec<String> = flags.iter().map(|s| s.to_string()).collect();

    cmd_args.push(user_arg.to_string());
    cmd_args.push(userlist.to_string());

    cmd_args.push(pass_arg.to_string());
    cmd_args.push(passlist.to_string());

    cmd_args.push("-o".to_string());
    cmd_args.push(output_file.to_string());

    cmd_args.push(target.to_string());
    cmd_args.push(protocol.to_string());

    let mut final_cmd = base_cmd.to_string();
    let mut final_args = cmd_args;

    if use_proxy {
        final_args.insert(0, final_cmd);
        final_cmd = "proxychains".to_string();
    }

    (final_cmd, final_args)
}

#[cfg(test)]
#[path = "brute_tests.rs"]
mod tests;
