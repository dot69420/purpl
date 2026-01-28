use std::io::{BufRead, Write};
use std::fs::{self, File};
use chrono::Local;
use colored::*;
use lazy_static::lazy_static;
use regex::Regex;
use crate::history::{append_history, HistoryEntry};
use crate::executor::CommandExecutor;
use crate::io_handler::IoHandler;

#[derive(Debug, Clone)]
pub struct SniffProfile {
    pub name: String,
    pub description: String,
    pub filter: String, // tcpdump filter syntax
    pub args: Vec<&'static str>,
}

impl SniffProfile {
    pub fn new(name: &str, description: &str, filter: &str, args: &[&'static str]) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            filter: filter.to_string(),
            args: args.to_vec(),
        }
    }
}

pub fn run_sniffer(interface_input: &str, _use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // 1. Check Root
    let mut use_sudo = false;
    if !executor.is_root() {
        io.print(&format!("\n{} {} [Y/n]: ", "[!]".red(), "Packet sniffing requires ROOT privileges. Attempt to elevate with sudo?".yellow().bold()));
        io.flush();
        let input = io.read_line();
        
        if input.trim().eq_ignore_ascii_case("y") || input.trim().is_empty() {
             use_sudo = true;
             // Simple sudo check
             if executor.execute("sudo", &["-v"]).is_err() {
                 io.println(&format!("{}", "[-] Sudo authentication failed. Aborting.".red()));
                 return;
             }
        } else {
             io.println(&format!("{}", "[-] Root required. Exiting.".red()));
             return;
        }
    }

    io.println(&format!("\n{}", "--- Packet Sniffer Module (Tcpdump) ---".magenta().bold()));

    // 2. Select Interface
    let interface = if interface_input.is_empty() {
        select_interface(use_sudo, executor, io).unwrap_or_else(|| "".to_string())
    } else {
        interface_input.to_string()
    };

    if interface.is_empty() {
        return; // User cancelled
    }

    // 3. Select Filter Profile
    let profiles = vec![
        SniffProfile::new(
            "All Traffic",
            "Capture everything. Good for overview.",
            "", 
            &["-v"]
        ),
        SniffProfile::new(
            "HTTP/FTP/Telnet",
            "Focus on plaintext credentials (port 80, 21, 23).",
            "tcp port 80 or tcp port 21 or tcp port 23",
            &["-v", "-A"]
        ),
        SniffProfile::new(
            "DNS Traffic",
            "Monitor DNS queries (port 53).",
            "udp port 53",
            &["-v"]
        ),
        SniffProfile::new(
            "ICMP (Ping)",
            "Watch for ping requests/replies.",
            "icmp",
            &["-v"]
        ),
        SniffProfile::new(
            "Custom Filter",
            "Enter your own BPF filter syntax.",
            "",
            &["-v"]
        ),
    ];

    io.println(&format!("\n{}", "Select Capture Filter:".blue().bold()));
    for (i, profile) in profiles.iter().enumerate() {
        io.println(&format!("[{}] {} - {}", i + 1, profile.name.green(), profile.description));
    }

    io.print(&format!("\nChoose a profile [1-{}]: ", profiles.len()));
    io.flush();
    let input = io.read_line();
    let mut selected_profile = if let Ok(idx) = input.trim().parse::<usize>() {
        if idx > 0 && idx <= profiles.len() {
            profiles[idx - 1].clone()
        } else {
            profiles[0].clone()
        }
    } else {
        profiles[0].clone()
    };

    if selected_profile.name == "Custom Filter" {
        io.print("Enter custom BPF filter (e.g. 'host 1.2.3.4 and tcp port 80'): ");
        io.flush();
        selected_profile.filter = io.read_line().trim().to_string();
    }

    // 4. Select Mode
    io.println(&format!("\n{}", "Select Operation Mode:".blue().bold()));
    io.println("[1] Passive Capture (Save to .pcap file)");
    io.println("[2] Live Analysis (Print parsed traffic to screen)");
    
    io.print("\nSelect mode [1-2]: ");
    io.flush();
    let mode_in = io.read_line();
    let mode = match mode_in.trim() {
        "2" => "live",
        _ => "capture"
    };

    // 5. Setup Output
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/packets/{}", date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    
    let pcap_file = format!("{}/capture.pcap", output_dir);
    let report_file = format!("{}/report.txt", output_dir);

    io.println(&format!("{}", format!("\n[+] Starting {} on {}", selected_profile.name, interface).green()));
    if !selected_profile.filter.is_empty() {
        io.println(&format!("    Filter: {}", selected_profile.filter.cyan()));
    }

    if mode == "capture" {
        io.println(&format!("[+] Saving packets to: {}", pcap_file));
        
        let mut args = vec!["-i", &interface, "-w", &pcap_file];
        if !selected_profile.filter.is_empty() {
            args.push(&selected_profile.filter);
        }

        let cmd = if use_sudo { "sudo" } else { "tcpdump" };
        let mut final_args = Vec::new();
        if use_sudo {
            final_args.push("tcpdump");
        }
        final_args.extend(args);

        io.println(&format!("\nRunning: {} {}", cmd, final_args.join(" ")));
        io.println("Press Ctrl+C to stop capture...");

        let _ = executor.execute(cmd, &final_args); // This blocks until Ctrl+C usually

        io.println(&format!("\n{}", "Capture saved.".green()));
        let _ = append_history(&HistoryEntry::new("Sniffer (PCAP)", &interface, &pcap_file));

    } else {
        // LIVE MODE
        io.println("[+] Live parsing... Press Ctrl+C to stop.");
        
        // Ensure -l (buffered) and -A (ascii) are present for live parsing
        let mut args = selected_profile.args.clone();
        if !args.contains(&"-l") { args.push("-l"); }
        if !args.contains(&"-A") { args.push("-A"); } // Force ASCII for live view
        
        let (tcpdump_cmd, tcpdump_args) = build_sniffer_command("tcpdump", &interface, &args, &selected_profile.filter, use_sudo);
        let args_str: Vec<&str> = tcpdump_args.iter().map(|s| s.as_str()).collect();

        let reader = executor.spawn_stdout(&tcpdump_cmd, &args_str).expect("Failed to run tcpdump");
        
        // We log what we see to a text report too
        let mut file = File::create(&report_file).expect("Failed to create report file");
        let mut current_packet = String::new();

        for line in reader.lines() {
            if let Ok(l) = line {
                if l.contains(" IP ") {
                     if !current_packet.is_empty() {
                         process_packet_block(&current_packet, &mut file, io);
                         current_packet.clear();
                     }
                     current_packet.push_str(&l);
                     current_packet.push('\n');
                } else {
                    current_packet.push_str(&l);
                    current_packet.push('\n');
                }
            }
        }
        if !current_packet.is_empty() {
             process_packet_block(&current_packet, &mut file, io);
        }
        
        io.println(&format!("{}", "Analysis finished.".yellow()));
        let _ = append_history(&HistoryEntry::new("Sniffer (Live)", &interface, "Finished"));
    }
}

fn select_interface(use_sudo: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) -> Option<String> {
    let cmd = if use_sudo { "sudo" } else { "ip" };
    let args = if use_sudo { vec!["ip", "link", "show"] } else { vec!["link", "show"] };

    if let Ok(output) = executor.execute_output(cmd, &args) {
        let out_str = String::from_utf8_lossy(&output.stdout);
        let mut interfaces = Vec::new();
        
        for line in out_str.lines() {
            // parsing lines like: "1: lo: <LOOPBACK..."
            if let Some(start) = line.find(": ") {
                if let Some(end) = line[start+2..].find(": ") {
                    let iface = line[start+2 .. start+2+end].trim();
                    interfaces.push(iface.to_string());
                }
            }
        }

        if interfaces.is_empty() {
            io.println(&format!("{}", "[-] No interfaces found via 'ip link'.".yellow()));
            io.print("Enter interface manually: ");
            io.flush();
            let manual = io.read_line().trim().to_string();
            if manual.is_empty() { return None; }
            return Some(manual);
        }

        io.println(&format!("\n{}", "Available Interfaces:".cyan().bold()));
        for (i, iface) in interfaces.iter().enumerate() {
            io.println(&format!("[{}] {}", i + 1, iface));
        }
        io.println("[0] Manual Input");

        io.print("\nSelect interface: ");
        io.flush();
        let input = io.read_line();
        let choice = input.trim().parse::<usize>().unwrap_or(999);

        if choice == 0 {
             io.print("Enter interface manually: ");
             io.flush();
             let manual = io.read_line().trim().to_string();
             if manual.is_empty() { return None; }
             return Some(manual);
        }

        if choice > 0 && choice <= interfaces.len() {
            return Some(interfaces[choice - 1].clone());
        }
    }
    
    // Fallback if command fails
    io.print("Enter interface manually: ");
    io.flush();
    let manual = io.read_line().trim().to_string();
    if manual.is_empty() { return None; }
    Some(manual)
}

lazy_static! {
    static ref RE_HEADER: Regex = Regex::new(r"(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s([\w\.-]+)\s>\s([\w\.-]+):\s(.*)").unwrap();
}

fn process_packet_block(block: &str, file: &mut File, io: &dyn IoHandler) {
    let lines: Vec<&str> = block.lines().collect();
    if lines.is_empty() { return; }

    let header = lines[0];
    
    if let Some(caps) = RE_HEADER.captures(header) {
        let time = &caps[1];
        let src = &caps[2];
        let dst = &caps[3];
        let flags = &caps[4];

        let payload: String = lines.iter().skip(1).cloned().collect::<Vec<&str>>().join("\n");
        let content_type = detect_protocol(flags, &payload);
        let clean_payload = extract_readable(&payload);

        // Screen
        io.println(&format!("{}", "-".repeat(50).dimmed()));
        io.println(&format!("{} {} -> {}", time.blue(), src.green(), dst.red()));
        io.println(&format!("Type: {}", content_type.yellow().bold()));
        if !clean_payload.is_empty() {
            io.println(&format!("Content:\n{}", clean_payload.white()));
        }

        // Report
        writeln!(file, "--------------------------------------------------").unwrap();
        writeln!(file, "Time: {}", time).unwrap();
        writeln!(file, "Source: {}", src).unwrap();
        writeln!(file, "Destination: {}", dst).unwrap();
        writeln!(file, "Type: {}", content_type).unwrap();
        writeln!(file, "Content:\n{}", clean_payload).unwrap();
    }
}

fn detect_protocol(flags: &str, payload: &str) -> String {
    if payload.contains("HTTP/") || payload.contains("GET ") || payload.contains("POST ") {
        return "HTTP (Unencrypted)".to_string();
    }
    if payload.contains("USER ") || payload.contains("PASS ") {
        return "FTP/Telnet (Credentials)".to_string();
    }
    if flags.contains("UDP") || flags.contains("domain") {
        return "DNS".to_string();
    }
    if flags.contains("Flags [S]") {
        return "TCP SYN".to_string();
    }
    "TCP/IP Raw".to_string()
}

fn extract_readable(payload: &str) -> String {
    let mut clean = String::new();
    for line in payload.lines() {
        let filtered: String = line.chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .collect();
        
        if filtered.len() > 3 {
            clean.push_str(&filtered);
            clean.push('\n');
        }
    }
    clean
}

pub fn build_sniffer_command(
    base_cmd: &str,
    interface: &str,
    args: &[&str],
    filter: &str,
    use_sudo: bool
) -> (String, Vec<String>) {
    let mut final_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    final_args.push("-i".to_string());
    final_args.push(interface.to_string());
    
    // For live analysis helper, usually needs unbuffered
    if !final_args.contains(&"-l".to_string()) {
        final_args.push("-l".to_string());
    }

    if !filter.is_empty() {
        final_args.push(filter.to_string());
    }
    
    let mut final_cmd = base_cmd.to_string();
    
    if use_sudo {
        final_args.insert(0, final_cmd.to_string());
        final_cmd = "sudo".to_string();
    }

    (final_cmd, final_args)
}

#[cfg(test)]
#[path = "sniffer_tests.rs"]
mod tests;
