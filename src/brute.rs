use std::process::{Command, Stdio};
use std::io::{self, Write};
use std::path::Path;
use std::fs;
use chrono::Local;
use colored::*;
use crate::history::{append_history, HistoryEntry};

#[derive(Debug, Clone)]
struct BruteProfile {
    name: String,
    description: String,
    userlist: String,
    passlist: String,
    flags: Vec<&'static str>,
}

impl BruteProfile {
    fn new(name: &str, description: &str, userlist: &str, passlist: &str, flags: &[&'static str]) -> Self {
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

pub fn run_brute_force(target: &str, use_proxy: bool) {
    // 1. Validation
    if Command::new("hydra").arg("-h").output().is_err() {
        println!("{}", "[-] 'hydra' not found. Please install it (sudo apt install hydra).".red());
        return;
    }

    if target.trim().is_empty() {
        println!("{}", "[!] Target cannot be empty.".red());
        return;
    }

    // 2. Select Protocol
    println!("\n{}", "Select Target Protocol:".blue().bold());
    let protocols = vec!["ssh", "ftp", "telnet", "rdp", "mysql", "postgresql"];
    for (i, p) in protocols.iter().enumerate() {
        println!("[{}] {}", i + 1, p);
    }
    
    print!("\nChoose protocol [1-{}]: ", protocols.len());
    let _ = io::stdout().flush();
    let mut p_in = String::new();
    io::stdin().read_line(&mut p_in).unwrap_or_default();
    
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
        "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/metasploit/unix_users.txt",
        "wordlists/users.txt"
    ]).unwrap_or_else(|| "manual".to_string());

    // Common Passwords
    let pass_list_path = find_wordlist(&[
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
    println!("\n{}", "Select Attack Profile:".blue().bold());
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

    // Handle Input/Manual
    let user_arg;
    if selected_profile.name.contains("Single User") {
        print!("{}", "Enter Username to target: ".yellow());
        let _ = io::stdout().flush();
        let mut user = String::new();
        io::stdin().read_line(&mut user).unwrap_or_default();
        selected_profile.userlist = user.trim().to_string();
        user_arg = "-l".to_string(); // Little l for single user
    } else if selected_profile.userlist == "manual" {
         print!("{}", "Enter path to USER list: ".yellow());
         let _ = io::stdout().flush();
         let mut path = String::new();
         io::stdin().read_line(&mut path).unwrap_or_default();
         selected_profile.userlist = path.trim().to_string();
         user_arg = "-L".to_string(); // Big L for list
    } else {
        user_arg = "-L".to_string();
    }

    if selected_profile.passlist == "manual" {
         print!("{}", "Enter path to PASSWORD list: ".yellow());
         let _ = io::stdout().flush();
         let mut path = String::new();
         io::stdin().read_line(&mut path).unwrap_or_default();
         selected_profile.passlist = path.trim().to_string();
    }
    let pass_arg = "-P".to_string(); // Big P for list (usually) - wait, hydra uses -P for list, -p for single

    // 6. Setup Output
    let safe_target = target.replace("://", "_").replace('/', "_");
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/brute/{}/{}", safe_target, date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    let output_file = format!("{}/hydra.txt", output_dir);

    println!("{}", format!("\n[+] Starting Hydra on {}://{}", protocol, target).green());
    println!("[+] Saving output to: {}", output_file);

    // 7. Execute
    // hydra [flags] -L user -P pass target protocol
    let mut cmd_args = selected_profile.flags.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    
    // Add User arg
    cmd_args.push(user_arg);
    cmd_args.push(selected_profile.userlist);

    // Add Pass arg
    cmd_args.push(pass_arg);
    cmd_args.push(selected_profile.passlist);

    // Output file
    cmd_args.push("-o".to_string());
    cmd_args.push(output_file.clone());

    // Target & Proto
    cmd_args.push(target.to_string());
    cmd_args.push(protocol.to_string());

    let mut final_cmd = "hydra";
    if use_proxy {
        cmd_args.insert(0, "hydra".to_string());
        final_cmd = "proxychains";
    }

    let final_args_str: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();

    // Hydra outputs to stderr largely for status, stdout for found
    let status = Command::new(final_cmd)
        .args(&final_args_str)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();

    match status {
        Ok(s) => {
            if s.success() {
                // Check if output file has content (successes)
                if let Ok(content) = fs::read_to_string(&output_file) {
                    if !content.trim().is_empty() {
                         println!("{}", "\n[+] Credentials Found!".green().bold());
                         println!("{}", content);
                         let _ = append_history(&HistoryEntry::new("BruteForce", target, "CRACKED"));
                    } else {
                         println!("{}", "\n[-] No credentials found.".yellow());
                         let _ = append_history(&HistoryEntry::new("BruteForce", target, "Failed"));
                    }
                }
            } else {
                println!("{}", "\n[!] Hydra failed or was interrupted.".yellow());
            }
        },
        Err(e) => println!("{} {}", "[!] Failed to start process:".red(), e),
    }
}
