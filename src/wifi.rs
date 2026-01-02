use std::process::{Command, Stdio};
use std::io::{self, Write};
use colored::*;
use crate::history::{append_history, HistoryEntry};

pub fn run_wifi_audit(interface: &str, _use_proxy: bool) {
    let mut use_sudo = false;
    if unsafe { libc::geteuid() } != 0 {
        print!("\n{} {} [Y/n]: ", "[!]".red(), "WiFi Audit requires ROOT. Attempt to elevate with sudo?".yellow().bold());
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap_or_default();
        
        if input.trim().eq_ignore_ascii_case("y") || input.trim().is_empty() {
             use_sudo = true;
             // Validate sudo credentials immediately
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

    let run_cmd = |cmd: &str, args: &[&str]| {
        let mut final_cmd = cmd;
        let mut final_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        if use_sudo {
            final_args.insert(0, final_cmd.to_string());
            final_cmd = "sudo";
        }
        
        let final_args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();
        
        // If sudo is used, we might need to inherit stdio for some commands if sudo -v timed out,
        // but generally sudo -v covers us.
        if cmd == "wifite" {
             // Wifite needs interactive stdin/out
             let _ = Command::new(final_cmd)
                .args(&final_args_str)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status();
        } else {
             // Others can be silent-ish
             let _ = Command::new(final_cmd)
                .args(&final_args_str)
                .output();
        }
    };

    println!("{}", format!("[+] Starting WiFi Audit on {}", interface).green());

    // Kill interfering processes
    println!("{}", "[+] Killing interfering processes...".blue());
    run_cmd("airmon-ng", &["check", "kill"]);

    // Randomize MAC
    println!("{}", "[+] Randomizing MAC address...".blue());
    run_cmd("ip", &["link", "set", interface, "down"]);
    run_cmd("macchanger", &["-r", interface]);
    run_cmd("ip", &["link", "set", interface, "up"]);

    // Enable Monitor Mode
    println!("{}", "[+] Enabling Monitor Mode...".blue());
    run_cmd("airmon-ng", &["start", interface]);

    // Find new interface name (often wlan0mon)
    let iwconfig = Command::new("iwconfig").output().expect("Failed to run iwconfig");
    let output = String::from_utf8_lossy(&iwconfig.stdout);
    
    // Simple heuristic to find monitor interface
    let mon_iface = output.lines()
        .find(|line| line.contains("Mode:Monitor"))
        .map(|line| line.split_whitespace().next().unwrap_or(interface))
        .unwrap_or(interface); // Fallback to original if not found (some cards don't change name)

    println!("{}", format!("[+] Monitor mode enabled on: {}", mon_iface).green());

    println!("\n{}", "[+] Launching Wifite... (Press Ctrl+C to stop)".yellow());
    
    // Launch Wifite
    run_cmd("wifite", &["-i", mon_iface, "--kill"]);
    
    let _ = append_history(&HistoryEntry::new("Wifite", interface, "Executed"));

    // Cleanup attempt (simple)
    println!("\n{}", "[+] Cleaning up...".blue());
    run_cmd("airmon-ng", &["stop", mon_iface]);
    run_cmd("systemctl", &["start", "NetworkManager"]);
}
