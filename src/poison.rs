use crate::executor::CommandExecutor;
use crate::history::{HistoryEntry, append_history};
use crate::io_handler::IoHandler;
use chrono::Local;
use std::fs;
use std::path::Path;

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

#[derive(Debug, Clone)]
pub struct PoisonConfig {
    pub interface: String,
    pub profile: PoisonProfile,
    pub use_sudo: bool,
}

pub fn configure_poisoning(
    interface_input: &str,
    executor: &dyn CommandExecutor,
    io: &dyn IoHandler,
) -> Option<PoisonConfig> {
    let mut use_sudo = false;
    if !executor.is_root() {
        match crate::ui::ask_and_enable_sudo(executor, io, Some("LAN Poisoning")) {
            Ok(true) => use_sudo = true,
            Ok(false) => {
                io.println("[-] Root required. Exiting.");
                return None;
            }
            Err(_) => return None,
        }
    }

    if executor.execute_output("responder", &["--help"]).is_err() {
        io.println("[-] 'responder' not found. Please install it.");
        return None;
    }

    let interface = if interface_input.is_empty() {
        select_interface(executor, io)
    } else {
        interface_input.to_string()
    };

    if interface.is_empty() {
        io.println("[!] No interface selected.");
        return None;
    }

    let profiles = vec![
        PoisonProfile::new("Analyze Mode", "Passive. Listen only.", &["-A"]),
        PoisonProfile::new(
            "Basic Poisoning",
            "Respond to LLMNR/NBT-NS.",
            &["-w", "-r", "-f"],
        ),
        PoisonProfile::new(
            "Aggressive",
            "Force WPAD + DHCP.",
            &["-w", "-r", "-f", "--wpad", "--dhcp-wpad"],
        ),
    ];

    io.println("\nSelect Poisoning Profile:");
    for (i, p) in profiles.iter().enumerate() {
        io.println(&format!("[{}] {} - {}", i + 1, p.name, p.description));
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

    Some(PoisonConfig {
        interface,
        profile,
        use_sudo,
    })
}

pub fn execute_poisoning(
    config: PoisonConfig,
    _use_proxy: bool,
    executor: &dyn CommandExecutor,
    io: &dyn IoHandler,
) {
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/poison/{}", date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");

    io.println(&format!("\n[+] Starting Responder on {}", config.interface));
    io.println(&format!("[+] Profile: {}", config.profile.name));
    io.println("[!] Press Ctrl+C to stop.");

    let (responder_cmd, responder_args) = build_responder_command(
        "responder",
        &config.interface,
        &config.profile.flags,
        config.use_sudo,
    );
    let responder_args_str: Vec<&str> = responder_args.iter().map(|s| s.as_str()).collect();

    let status = executor.execute_streamed(
        &responder_cmd,
        &responder_args_str,
        "",
        None,
        Box::new(|line| io.println(line)),
    );

    if Path::new("logs").exists() {
        let _ = fs::rename("logs", Path::new(&output_dir).join("logs"));
        io.println(&format!("[+] Logs moved to {}", output_dir));
    }

    match status {
        Ok(_) => {
            let _ = append_history(&HistoryEntry::new(
                "Poisoning",
                &config.interface,
                "Executed",
            ));
        }
        Err(e) => io.println(&format!("[!] Failed to start process: {}", e)),
    }
}

pub fn run_poisoning(
    interface_input: &str,
    use_proxy: bool,
    executor: &dyn CommandExecutor,
    io: &dyn IoHandler,
) {
    if let Some(config) = configure_poisoning(interface_input, executor, io) {
        execute_poisoning(config, use_proxy, executor, io);
    }
}

pub fn build_responder_command(
    base_cmd: &str,
    interface: &str,
    flags: &[&str],
    use_sudo: bool,
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
    let output = executor.execute_output("ip", &["link"]);
    if let Ok(out) = output {
        let out_str = String::from_utf8_lossy(&out.stdout);
        let mut ifaces = Vec::new();

        for line in out_str.lines() {
            if let Some(start) = line.find(": ") {
                if let Some(end) = line[start + 2..].find(':') {
                    let iface = &line[start + 2..start + 2 + end];
                    if iface != "lo" {
                        ifaces.push(iface.trim().to_string());
                    }
                }
            }
        }

        if ifaces.is_empty() {
            return "eth0".to_string();
        }

        io.println("\nAvailable Interfaces:");
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
