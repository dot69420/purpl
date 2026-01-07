
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
    // 1. Check Dependencies (bluetoothctl is the modern standard)
    if executor.execute_output("bluetoothctl", &["--version"]).is_err() {
        io.println(&format!("{}", "[-] 'bluetoothctl' not found. Please install 'bluez-utils'.".red()));
        return;
    }

    // 2. Check/Reset Adapter
    io.println(&format!("{}", "[*] Checking Bluetooth Adapter status...".blue()));
    let _ = executor.execute_output("rfkill", &["unblock", "bluetooth"]);
    // bluetoothctl power on is the modern equivalent of hciconfig up, 
    // but requires interactive or just relying on the service.
    // We can try 'bluetoothctl power on'
    let _ = executor.execute_output("bluetoothctl", &["power", "on"]);

    // 3. Define Profiles
    let profiles = vec![
        BtProfile::new(
            "Scan (General)",
            "Discover visible Bluetooth devices (Classic & LE).",
            "bluetoothctl",
            &["--timeout", "10", "scan", "on"],
            false
        ),
        BtProfile::new(
            "Service Discovery",
            "Enumerate services on a target MAC (bluetoothctl info).",
            "bluetoothctl",
            &["info"],
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

    // Special Check for Deprecated Tools
    if profile.cmd == "l2ping" {
        if executor.execute_output("l2ping", &[]).is_err() {
             io.println(&format!("{}", "[-] 'l2ping' not found. This tool is deprecated and might be missing from modern 'bluez-utils'.\n    Try installing 'bluez-deprecated-tools' or equivalent.".red()));
             return;
        }
    }

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
    // Check Root for specific commands
    let mut use_sudo = false;
    if profile.name.contains("Stress") {
        if !executor.is_root() {
             io.print(&format!("\n{} {} [Y/n]: ", "[!]".red(), "This profile requires ROOT. Attempt to elevate with sudo?".yellow().bold()));
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
    }

    let (cmd_bin, args) = build_bluetooth_command(profile.cmd, &profile.args, &target_mac, profile.requires_input, use_sudo);
    let args_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    // Special handling for bluetoothctl scan to parse it nicely
    if profile.cmd == "bluetoothctl" && args.contains(&"scan".to_string()) {
        io.println("Scanning for 10 seconds...");
        // 1. Run Scan to populate cache (ignore output)
        let _ = executor.execute_output(&cmd_bin, &args_str);
        
        // Sleep briefly to ensure cache persistence/DBus sync
        #[cfg(not(test))]
        std::thread::sleep(std::time::Duration::from_secs(2));

        // 2. Run 'devices' to get the clean list
        let devices_output = executor.execute_output("bluetoothctl", &["devices"]).expect("Failed to list devices");
        let stdout = String::from_utf8_lossy(&devices_output.stdout);
        
        // Write raw to file
        let _ = fs::write(&output_file, stdout.as_bytes());
        
        if stdout.trim().is_empty() {
            io.println(&format!("{}", "[-] No devices found or 'bluetoothctl devices' returned empty.".yellow()));
            // Debug info
            io.println(&format!("DEBUG: Exit Status: {}", devices_output.status));
            io.println(&format!("DEBUG: Stderr: {}", String::from_utf8_lossy(&devices_output.stderr)));
        } else {
            // Print nicely
            io.println(&format!("{}", "\nDiscovered Devices:".blue().bold()));
            // bluetoothctl devices output: Device XX:XX:XX:XX:XX:XX Name...
            for line in stdout.lines() { 
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0] == "Device" {
                    let mac = parts[1];
                    let name = parts[2..].join(" ");
                    io.println(&format!("  {}  {}", mac.yellow(), name));
                }
            }
        }
    } else if profile.cmd == "l2ping" {
        // Safe execution for infinite stream/flood
        io.println(&format!("{}", "[-] Running in interactive/stream mode. Press Ctrl+C to stop.".yellow()));
        let status = executor.execute(&cmd_bin, &args_str);
        
        if status.is_err() {
            io.println(&format!("{}", "[-] Execution failed.".red()));
        } else {
             io.println(&format!("{}", "\n[+] Command finished.".green()));
        }
        // We don't write output to file for l2ping flood as it's massive/infinite.
        let _ = fs::write(&output_file, "Flood ping executed interactively/streamed.");
    } else {
        // Stream other commands
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
    requires_input: bool,
    use_sudo: bool
) -> (String, Vec<String>) {
    let mut cmd_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    if requires_input && !target_mac.is_empty() {
        cmd_args.push(target_mac.to_string());
    }
    
    let mut final_cmd = base_cmd.to_string();
    if use_sudo {
        cmd_args.insert(0, final_cmd);
        final_cmd = "sudo".to_string();
    }
    
    (final_cmd, cmd_args)
}

#[cfg(test)]
#[path = "bluetooth_tests.rs"]
mod tests;
