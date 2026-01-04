use std::io::Write;
use std::fs;
use chrono::Local;
use colored::*;
use crate::history::{append_history, HistoryEntry};
use crate::executor::CommandExecutor;
use crate::io_handler::IoHandler;

#[derive(Debug, Clone)]
pub struct BtProfile {
    pub name: String,
    pub description: String,
    pub cmd: &'static str,
    pub args: Vec<&'static str>,
    pub requires_input: bool, // If true, we need a MAC address target
}

impl BtProfile {
    pub fn new(name: &str, description: &str, cmd: &'static str, args: &[&'static str], requires_input: bool) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            cmd,
            args: args.to_vec(),
            requires_input,
        }
    }
}

pub fn run_bluetooth_attacks(input_arg: &str, _use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // 1. Check Dependencies
    if executor.execute_output("hcitool", &["--help"]).is_err() {
        io.println(&format!("{}", "[-] 'BlueZ' tools (hcitool) not found. Please install them (sudo pacman -S bluez-utils).".red()));
        return;
    }

    // 2. Check/Reset Adapter
    io.println(&format!("{}", "[*] Checking Bluetooth Adapter status...".blue()));
    let _ = executor.execute_output("rfkill", &["unblock", "bluetooth"]);
    let _ = executor.execute_output("hciconfig", &["hci0", "up"]);

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
    io.println(&format!("\n{}", "Select Bluetooth Module:".blue().bold()));
    for (i, p) in profiles.iter().enumerate() {
        io.println(&format!("[{}] {} - {}", i + 1, p.name.green(), p.description));
    }

    io.print(&format!("\nChoose a profile [1-{}]: ", profiles.len()));
    io.flush();
    let choice = io.read_line();

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
        io.print(&format!("{}", "Enter Target MAC Address (XX:XX:XX:XX:XX:XX): ".yellow()));
        io.flush();
        let mac = io.read_line();
        target_mac = mac.trim().to_string();
        
        if target_mac.is_empty() {
            io.println(&format!("{}", "[!] Target MAC is required for this profile.".red()));
            return;
        }
    }

    // 6. Setup Output
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/bluetooth/{}", date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    let output_file = format!("{}/scan.txt", output_dir);

    io.println(&format!("{}", format!("\n[+] Starting {}...", profile.name).green()));
    io.println(&format!("[+] Saving output to: {}", output_file));

    // 7. Execute
    let (cmd_bin, args) = build_bluetooth_command(profile.cmd, &profile.args, &target_mac, profile.requires_input);
    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    // Check Root for specific commands
    if profile.name.contains("Low Energy") || profile.name.contains("Stress") {
        if !executor.is_root() {
             io.println(&format!("{}", "[!] This profile requires ROOT. Try running with sudo.".red()));
             return;
        }
        // If we are root, we just run.
    }

    // Special handling for hcitool scan to parse it nicely
    if profile.cmd == "hcitool" && args.contains(&"scan".to_string()) {
        // Run and capture output
        let output = executor.execute_output(&cmd_bin, &args_str).expect("Failed to run scan");
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Write raw to file
        let _ = fs::write(&output_file, stdout.as_bytes());
        
        // Print nicely
        io.println(&format!("{}", "\nDiscovered Devices:".blue().bold()));
        for line in stdout.lines().skip(1) { // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let mac = parts[0];
                let name = parts[1..].join(" ");
                io.println(&format!("  {}  {}", mac.yellow(), name));
            }
        }
    } else {
        // Stream other commands (like ping flood or sdp browse)
        // With executor refactor, if we use execute_output we lose streaming.
        // We will use execute() which inherits stdio in ShellExecutor,
        // but we wanted to redirect stdout to file.
        // The trait currently doesn't support file redirection easily.
        // We will use execute_output and write to file manually.

        let output = executor.execute_output(&cmd_bin, &args_str).expect("Failed to run command");
        // Write stdout to file
        let _ = fs::write(&output_file, output.stdout);

        io.println(&format!("{}", "\n[+] Command finished.".green()));
        io.println(&format!("Check {} for results.", output_file));
    }

    let _ = append_history(&HistoryEntry::new("Bluetooth", &profile.name, "Executed"));
}

pub fn build_bluetooth_command(
    base_cmd: &str,
    args: &[&str],
    target_mac: &str,
    requires_input: bool
) -> (String, Vec<String>) {
    let mut cmd_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    if requires_input && !target_mac.is_empty() {
        cmd_args.push(target_mac.to_string());
    }
    (base_cmd.to_string(), cmd_args)
}

#[cfg(test)]
#[path = "bluetooth_tests.rs"]
mod tests;
