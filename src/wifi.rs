use std::process::{Command, Stdio};
use std::io::{self, Write};
use colored::*;
use crate::history::{append_history, HistoryEntry};

#[derive(Debug)]
struct WifiProfile {
    name: String,
    description: String,
    flags: Vec<String>,
}

impl WifiProfile {
    fn new(name: &str, description: &str, flags: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            flags: flags.iter().map(|s| s.to_string()).collect(),
        }
    }
}

fn select_wifi_profile() -> WifiProfile {
    println!("\n{}", "Select WiFi Audit Profile:".blue().bold());
    let profiles = vec![
        WifiProfile::new(
            "Auto-Pwn (Default)",
            "Standard Wifite run. Scans all networks, targets everything. (Best for general audit)",
            &["--kill"]
        ),
        WifiProfile::new(
            "WPS Only",
            "Focus on WPS vulnerabilities (PixieDust, PIN bruteforce). Fast & Effective.",
            &["--wps", "--kill"]
        ),
        WifiProfile::new(
            "WPA Handshake Capture",
            "Focus on capturing WPA/2 Handshakes for offline cracking.",
            &["--wpa", "--kill"]
        ),
        WifiProfile::new(
            "5GHz Only",
            "Scan and attack only 5GHz networks (requires 5GHz capable card).",
            &["-5", "--kill"]
        ),
        WifiProfile::new(
            "Target Specific",
            "Target a specific network by ESSID (Name).",
            &["--kill"] // Placeholder, we will ask for ESSID
        ),
        WifiProfile::new(
            "Silent/Stealth",
            "Avoid deauth flooding where possible (Experimental).",
            &["--no-deauths", "--kill"]
        ),
    ];

    for (i, profile) in profiles.iter().enumerate() {
        println!("[{}] {} - {}", i + 1, profile.name.green(), profile.description);
    }

    print!("\nChoose a profile [1-{}]: ", profiles.len());
    let _ = io::stdout().flush();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();

    if let Ok(idx) = input.trim().parse::<usize>() {
        if idx > 0 && idx <= profiles.len() {
            let mut selected = profiles.into_iter().nth(idx - 1).unwrap();
            
            // Handle Targeted Input
            if selected.name == "Target Specific" {
                print!("{}", "Enter Target ESSID (Name): ".yellow());
                let _ = io::stdout().flush();
                let mut essid = String::new();
                io::stdin().read_line(&mut essid).unwrap_or_default();
                let essid = essid.trim();
                if !essid.is_empty() {
                    selected.flags.push("-e".to_string());
                    selected.flags.push(essid.to_string());
                } else {
                    println!("{}", "[!] No ESSID provided. Reverting to default.".red());
                }
            }
            
            return selected;
        }
    }

    println!("{}", "[!] Invalid selection. Defaulting to 'Auto-Pwn'.".yellow());
    WifiProfile::new(
        "Auto-Pwn (Default)",
        "Standard Wifite run. Scans all networks, targets everything.",
        &["--kill"]
    )
}

pub fn run_wifi_audit(interface: &str, _use_proxy: bool) {
    let mut use_sudo = false;
    if unsafe { libc::geteuid() } != 0 {
        print!("\n{} {} [Y/n]: ", "[!]".red(), "WiFi Audit requires ROOT. Attempt to elevate with sudo?".yellow().bold());
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap_or_default();
        
        if input.trim().eq_ignore_ascii_case("y") || input.trim().is_empty() {
             use_sudo = true;
             let status = Command::new("sudo")
                .arg("-v")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status();
            
             if status.is_err() || !status.unwrap().success() {
                 println!("{}", "[-] Sudo authentication failed. Aborting.".red());
                 return;
             }
        } else {
             println!("{}", "[-] Root required. Exiting.".red());
             return;
        }
    }

    // Helper to run commands
    let run_cmd = |cmd: &str, args: &[&str], interactive: bool| {
        let mut final_cmd = cmd;
        let mut final_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        if use_sudo {
            final_args.insert(0, final_cmd.to_string());
            final_cmd = "sudo";
        }
        
        let final_args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();
        
        if interactive {
             let _ = Command::new(final_cmd)
                .args(&final_args_str)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status();
        } else {
             let _ = Command::new(final_cmd)
                .args(&final_args_str)
                .output();
        }
    };

    println!("{}", format!("[+] Starting WiFi Audit on {}", interface).green());

    // 1. Profile Selection
    let profile = select_wifi_profile();
    println!("{}", format!("\n[+] Selected Profile: {}", profile.name).green().bold());

    // 2. Kill interfering processes
    println!("{}", "[+] Killing interfering processes...".blue());
    run_cmd("airmon-ng", &["check", "kill"], false);

    // 3. Randomize MAC
    println!("{}", "[+] Randomizing MAC address...".blue());
    run_cmd("ip", &["link", "set", interface, "down"], false);
    run_cmd("macchanger", &["-r", interface], false);
    run_cmd("ip", &["link", "set", interface, "up"], false);

    // 4. Enable Monitor Mode
    println!("{}", "[+] Enabling Monitor Mode...".blue());
    run_cmd("airmon-ng", &["start", interface], false);

    // Find new interface name
    let iwconfig = Command::new("iwconfig").output().expect("Failed to run iwconfig");
    let output = String::from_utf8_lossy(&iwconfig.stdout);
    
    let mon_iface = output.lines()
        .find(|line| line.contains("Mode:Monitor"))
        .map(|line| line.split_whitespace().next().unwrap_or(interface))
        .unwrap_or(interface);

    println!("{}", format!("[+] Monitor mode enabled on: {}", mon_iface).green());

    println!("\n{}", "[+] Launching Wifite... (Press Ctrl+C to stop)".yellow());
    
    // 5. Execute Wifite with Profile Flags
    let mut wifite_args = vec!["-i", mon_iface];
    let profile_flags_str: Vec<&str> = profile.flags.iter().map(|s| s.as_str()).collect();
    wifite_args.extend(profile_flags_str);
    
    run_cmd("wifite", &wifite_args, true);
    
    let _ = append_history(&HistoryEntry::new("Wifite", interface, &format!("Executed: {}", profile.name)));

    // 6. Cleanup
    println!("\n{}", "[+] Cleaning up...".blue());
    run_cmd("airmon-ng", &["stop", mon_iface], false);
    run_cmd("systemctl", &["start", "NetworkManager"], false);
}
