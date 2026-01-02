use std::process::{Command, Stdio};
use std::io::{self, Write};
use std::fs;
use chrono::Local;
use colored::*;
use crate::history::{append_history, HistoryEntry};

#[derive(Debug, Clone)]
struct BtProfile {
    name: String,
    description: String,
    cmd: &'static str,
    args: Vec<&'static str>,
    requires_input: bool, // If true, we need a MAC address target
}

impl BtProfile {
    fn new(name: &str, description: &str, cmd: &'static str, args: &[&'static str], requires_input: bool) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            cmd,
            args: args.to_vec(),
            requires_input,
        }
    }
}

pub fn run_bluetooth_attacks(input_arg: &str, _use_proxy: bool) {
    // 1. Check Dependencies
    if Command::new("hcitool").arg("--help").output().is_err() {
        println!("{}", "[-] 'BlueZ' tools (hcitool) not found. Please install them (sudo pacman -S bluez-utils).".red());
        return;
    }

    // 2. Check/Reset Adapter
    println!("{}", "[*] Checking Bluetooth Adapter status...".blue());
    let _ = Command::new("rfkill").args(&["unblock", "bluetooth"]).output();
    let _ = Command::new("hciconfig").args(&["hci0", "up"]).output();

    // 3. Define Profiles
    let profiles = vec![
        BtProfile::new(
            "Scan (Classic)",
            "Discover visible Bluetooth devices (hcitool scan).",
            "hcitool",
            &["scan"],
            false
        ),
        BtProfile::new(
            "Scan (Low Energy)",
            "Discover BLE devices (IoT, Wearables) - Requires Root.",
            "hcitool",
            &["lescan"],
            false
        ),
        BtProfile::new(
            "Service Discovery",
            "Enumerate services on a target MAC (sdptool browse).",
            "sdptool",
            &["browse"],
            true
        ),
        BtProfile::new(
            "Ping Flood (Stress)",
            "L2CAP Ping Flood. Can disconnect/drain battery. (l2ping -f) - Requires Root.",
            "l2ping",
            &["-f"],
            true
        ),
    ];

    // 4. Select Profile
    println!("\n{}", "Select Bluetooth Module:".blue().bold());
    for (i, p) in profiles.iter().enumerate() {
        println!("[{}] {} - {}", i + 1, p.name.green(), p.description);
    }

    print!("\nChoose a profile [1-{}]: ", profiles.len());
    let _ = io::stdout().flush();
    let mut choice = String::new();
    io::stdin().read_line(&mut choice).unwrap_or_default();

    let profile = if let Ok(idx) = choice.trim().parse::<usize>() {
        if idx > 0 && idx <= profiles.len() {
            profiles[idx - 1].clone()
        } else {
            profiles[0].clone()
        }
    } else {
        profiles[0].clone()
    };

    // 5. Handle Input (MAC Address)
    let mut target_mac = input_arg.to_string();
    if profile.requires_input && target_mac.is_empty() {
        print!("{}", "Enter Target MAC Address (XX:XX:XX:XX:XX:XX): ".yellow());
        let _ = io::stdout().flush();
        let mut mac = String::new();
        io::stdin().read_line(&mut mac).unwrap_or_default();
        target_mac = mac.trim().to_string();
        
        if target_mac.is_empty() {
            println!("{}", "[!] Target MAC is required for this profile.".red());
            return;
        }
    }

    // 6. Setup Output
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/bluetooth/{}", date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    let output_file = format!("{}/scan.txt", output_dir);

    println!("{}", format!("\n[+] Starting {}...", profile.name).green());
    println!("[+] Saving output to: {}", output_file);

    // 7. Execute
    let mut cmd = Command::new(profile.cmd);
    let mut args: Vec<String> = profile.args.iter().map(|s| s.to_string()).collect();

    // Check Root for specific commands
    if profile.name.contains("Low Energy") || profile.name.contains("Stress") {
        if unsafe { libc::geteuid() } != 0 {
             println!("{}", "[!] This profile requires ROOT. Try running with sudo.".red());
             return;
        }
        // If we are root, we just run.
    }

    if profile.requires_input {
        args.push(target_mac.clone());
    }

    // Special handling for hcitool scan to parse it nicely
    if profile.cmd == "hcitool" && args.contains(&"scan".to_string()) {
        // Run and capture output
        let output = cmd.args(&args).output().expect("Failed to run scan");
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Write raw to file
        let _ = fs::write(&output_file, stdout.as_bytes());
        
        // Print nicely
        println!("{}", "\nDiscovered Devices:".blue().bold());
        for line in stdout.lines().skip(1) { // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let mac = parts[0];
                let name = parts[1..].join(" ");
                println!("  {}  {}", mac.yellow(), name);
            }
        }
    } else {
        // Stream other commands (like ping flood or sdp browse)
        let _ = cmd.args(&args)
            .stdout(fs::File::create(&output_file).expect("Failed to open log"))
            .stderr(Stdio::inherit()) // Print errors to screen
            .status();
            
        println!("{}", "\n[+] Command finished.".green());
        // For tools that stream to file, we might want to read it back or just tell user where it is
        println!("Check {} for results.", output_file);
    }

    let _ = append_history(&HistoryEntry::new("Bluetooth", &profile.name, "Executed"));
}