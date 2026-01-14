
use std::fs;
use std::path::Path;
use chrono::Local;
use colored::*;
use crate::history::{append_history, HistoryEntry};
use crate::executor::CommandExecutor;
use crate::io_handler::IoHandler;

#[derive(Debug)]
pub struct WifiProfile {
    pub name: String,
    pub description: String,
    pub flags: Vec<String>,
}

impl WifiProfile {
    pub fn new(name: &str, description: &str, flags: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            flags: flags.iter().map(|s| s.to_string()).collect(),
        }
    }
}

fn select_wifi_profile(io: &dyn IoHandler) -> WifiProfile {
    io.println(&format!("\n{}", "Select WiFi Audit Profile:".blue().bold()));
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
        io.println(&format!("[{}] {} - {}", i + 1, profile.name.green(), profile.description));
    }

    io.print(&format!("\nChoose a profile [1-{}]: ", profiles.len()));
    io.flush();
    let input = io.read_line();

    if let Ok(idx) = input.trim().parse::<usize>() {
        if idx > 0 && idx <= profiles.len() {
            let mut selected = profiles.into_iter().nth(idx - 1).unwrap();
            
            // Handle Targeted Input
            if selected.name == "Target Specific" {
                io.print(&format!("{}", "Enter Target ESSID (Name): ".yellow()));
                io.flush();
                let essid = io.read_line();
                let essid = essid.trim();
                if !essid.is_empty() {
                    selected.flags.push("-e".to_string());
                    selected.flags.push(essid.to_string());
                } else {
                    io.println(&format!("{}", "[!] No ESSID provided. Reverting to default.".red()));
                }
            }
            
            return selected;
        }
    }

    io.println(&format!("{}", "[!] Invalid selection. Defaulting to 'Auto-Pwn'.".yellow()));
    WifiProfile::new(
        "Auto-Pwn (Default)",
        "Standard Wifite run. Scans all networks, targets everything.",
        &["--kill"]
    )
}

pub fn run_wifi_audit(interface: &str, _use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    let mut use_sudo = false;
    if !executor.is_root() {
        io.print(&format!("\n{} {} [Y/n]: ", "[!]".red(), "WiFi Audit requires ROOT. Attempt to elevate with sudo?".yellow().bold()));
        io.flush();
        let input = io.read_line();
        
        if input.trim().eq_ignore_ascii_case("y") || input.trim().is_empty() {
             use_sudo = true;
             let status = executor.execute("sudo", &["-v"]);
            
             if status.is_err() || !status.unwrap().success() {
                 io.println(&format!("{}", "[-] Sudo authentication failed. Aborting.".red()));
                 return;
             }
        } else {
             io.println(&format!("{}", "[-] Root required. Exiting.".red()));
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
             let _ = executor.execute(final_cmd, &final_args_str);
        } else {
             let _ = executor.execute_output(final_cmd, &final_args_str);
        }
    };

    io.println(&format!("{}", format!("[+] Starting WiFi Audit on {}", interface).green()));

    // 1. Profile Selection
    let profile = select_wifi_profile(io);
    io.println(&format!("{}", format!("\n[+] Selected Profile: {}", profile.name).green().bold()));

    // 2. Kill interfering processes
    io.println(&format!("{}", "[+] Killing interfering processes...".blue()));
    run_cmd("airmon-ng", &["check", "kill"], false);

    // 3. Randomize MAC
    io.println(&format!("{}", "[+] Randomizing MAC address...".blue()));
    run_cmd("ip", &["link", "set", interface, "down"], false);
    run_cmd("macchanger", &["-r", interface], false);
    run_cmd("ip", &["link", "set", interface, "up"], false);

    // 4. Enable Monitor Mode
    io.println(&format!("{}", "[+] Enabling Monitor Mode...".blue()));
    run_cmd("airmon-ng", &["start", interface], false);

    // Find new interface name
    let iwconfig = executor.execute_output("iwconfig", &[]).expect("Failed to run iwconfig");
    let output = String::from_utf8_lossy(&iwconfig.stdout);
    
    let mon_iface = output.lines()
        .find(|line| line.contains("Mode:Monitor"))
        .map(|line| line.split_whitespace().next().unwrap_or(interface))
        .unwrap_or(interface);

    io.println(&format!("{}", format!("[+] Monitor mode enabled on: {}", mon_iface).green()));

    io.println(&format!("\n{}", "[+] Launching Wifite... (Press Ctrl+C to stop)".yellow()));
    
    // 5. Execute Wifite with Profile Flags
    let profile_flags_str: Vec<&str> = profile.flags.iter().map(|s| s.as_str()).collect();
    let (wifite_cmd, wifite_args) = build_wifite_command("wifite", mon_iface, &profile_flags_str, use_sudo);
    
    let wifite_args_str: Vec<&str> = wifite_args.iter().map(|s| s.as_str()).collect();
    let _ = executor.execute(&wifite_cmd, &wifite_args_str);
    
    let _ = append_history(&HistoryEntry::new("Wifite", interface, &format!("Executed: {}", profile.name)));

    // 6. Cleanup & Save Results
    io.println(&format!("\n{}", "[+] Cleaning up...".blue()));
    run_cmd("airmon-ng", &["stop", mon_iface], false);
    run_cmd("systemctl", &["start", "NetworkManager"], false);

    // Move Results
    if Path::new("hs").exists() {
        let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let scan_dir = format!("scans/wifi/{}", date);
        
        // We don't create the dir first because rename needs the target to either not exist 
        // or be an empty dir (depending on OS). Safer to rename directly.
        if let Err(e) = fs::rename("hs", &scan_dir) {
            // If rename fails (e.g. across filesystems), we try create + copy logic
            let _ = fs::create_dir_all(&scan_dir);
            io.println(&format!("{} {} - Falling back to manual copy.", "[!] Failed to rename results:".red(), e));
            // (In a production app we'd recursive copy here, but for now we notify)
        } else {
            io.println(&format!("{}", format!("[+] Results saved to: {}", scan_dir).green()));
        }
    } else {
        io.println(&format!("{}", "[-] No Wifite results ('hs' folder) found.".yellow()));
    }
}

pub fn build_wifite_command(
    base_cmd: &str,
    interface: &str,
    flags: &[&str],
    use_sudo: bool
) -> (String, Vec<String>) {
    let mut args: Vec<String> = vec!["-i".to_string(), interface.to_string()];
    args.extend(flags.iter().map(|s| s.to_string()));

    let mut final_cmd = base_cmd.to_string();
    let mut final_args = args;

    if use_sudo {
        final_args.insert(0, final_cmd);
        final_cmd = "sudo".to_string();
    }

    (final_cmd, final_args)
}

#[cfg(test)]
#[path = "wifi_tests.rs"]
mod tests;
