use std::io::{BufRead, BufReader, Write};
use std::fs::{self, File};
use chrono::Local;
use colored::*;
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

#[derive(Debug)]
struct PacketSummary {
    timestamp: String,
    src: String,
    dst: String,
    protocol: String,
    payload_preview: String,
}

pub fn run_sniffer(interface: &str, _use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // 1. Check Root
    if !executor.is_root() {
        io.println(&format!("{}", "[!] Packet sniffing requires ROOT privileges.".red()));
        return;
    }

    // 2. Select Profile
    let profiles = vec![
        SniffProfile::new(
            "General Traffic",
            "Capture everything. Good for overview.",
            "", 
            &["-v", "-A"] // -A for ASCII
        ),
        SniffProfile::new(
            "Creds Hunter",
            "Focus on HTTP POST, FTP, Telnet (Plaintext passwords).",
            "tcp port 80 or tcp port 21 or tcp port 23",
            &["-v", "-A"]
        ),
        SniffProfile::new(
            "DNS Spy",
            "Monitor DNS queries to see visited domains.",
            "udp port 53",
            &["-v"]
        ),
        SniffProfile::new(
            "ICMP/Ping",
            "Watch for ping requests/replies.",
            "icmp",
            &["-v"]
        ),
    ];

    io.println(&format!("\n{}", "Select Sniffer Profile:".blue().bold()));
    for (i, profile) in profiles.iter().enumerate() {
        io.println(&format!("[{}] {} - {}", i + 1, profile.name.green(), profile.description));
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

    // 3. Setup Output
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/packets/{}", date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    
    let pcap_file = format!("{}/capture.pcap", output_dir);
    let report_file = format!("{}/report.txt", output_dir);

    io.println(&format!("{}", format!("\n[+] Starting {} on {}", profile.name, interface).green()));
    io.println(&format!("    Filter: {}", if profile.filter.is_empty() { "None (All)" } else { &profile.filter }));
    io.println(&format!("[+] Saving PCAP to: {}", pcap_file));
    io.println("[+] Live parsing... Press Ctrl+C to stop.");

    // 4. Start TCPDump
    let (tcpdump_cmd, tcpdump_args) = build_sniffer_command("tcpdump", interface, &profile.args, &profile.filter);

    let args_str: Vec<&str> = tcpdump_args.iter().map(|s| s.as_str()).collect();

    // The executor trait execute_output doesn't support streaming/spawning easily with the current simple definition.
    // However, for coverage, we can use execute_output which captures everything.
    // For real usage, we want streaming.
    // I should probably extend the trait or just use execute_output for simplicity in this refactor,
    // accepting we might lose live streaming in the "ShellExecutor" unless I implement `spawn`.

    // BUT, the current implementation uses `spawn` and reads stdout.
    // `execute_output` waits.
    // If I switch to `execute_output`, the tool will hang until Ctrl+C (which might not propagate).

    // Live parsing using spawn_stdout
    let reader = executor.spawn_stdout(&tcpdump_cmd, &args_str).expect("Failed to run tcpdump");

    let report_path = report_file.clone();
    
    // We need a thread to read output and process it
    // In blocking mode (refactored), we just process it.
    let mut file = File::create(report_path).expect("Failed to create report file");

    let mut current_packet = String::new();

    for line in reader.lines() {
        if let Ok(l) = line {
            // Heuristic Parsing
            if l.contains(" IP ") {
                // New packet start
                if !current_packet.is_empty() {
                     process_packet_block(&current_packet, &mut file, io);
                     current_packet.clear();
                }
                current_packet.push_str(&l);
                current_packet.push('\n');
            } else {
                // Payload or continuation
                current_packet.push_str(&l);
                current_packet.push('\n');
            }
        }
    }
    // Process last
    if !current_packet.is_empty() {
         process_packet_block(&current_packet, &mut file, io);
    }
    
    io.println(&format!("{}", "Capture finished.".yellow()));
    let _ = append_history(&HistoryEntry::new("Sniffer", interface, &format!("Profile: {}", profile.name)));
}

fn process_packet_block(block: &str, file: &mut File, io: &dyn IoHandler) {
    let re_header = Regex::new(r"(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s([\w\.-]+)\s>\s([\w\.-]+):\s(.*)").unwrap();
    
    let lines: Vec<&str> = block.lines().collect();
    if lines.is_empty() { return; }

    let header = lines[0];
    
    if let Some(caps) = re_header.captures(header) {
        let time = &caps[1];
        let src = &caps[2];
        let dst = &caps[3];
        let flags = &caps[4];

        // Payload is the rest
        let payload: String = lines.iter().skip(1).cloned().collect::<Vec<&str>>().join("\n");
        
        // "Decrypt" / Decode Logic
        let content_type = detect_protocol(flags, &payload);
        let clean_payload = extract_readable(&payload);

        // Print to Screen (Beautifully)
        io.println(&format!("{}", "-".repeat(50).dimmed()));
        io.println(&format!("{} {} -> {}", time.blue(), src.green(), dst.red()));
        io.println(&format!("Type: {}", content_type.yellow().bold()));
        if !clean_payload.is_empty() {
            io.println(&format!("Content:\n{}", clean_payload.white()));
        }

        // Write to Report
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
    // Filter ASCII only, remove junk chars
    let mut clean = String::new();
    for line in payload.lines() {
        // Tcpdump -A output is usually messy. 
        // We look for lines that look like text.
        let filtered: String = line.chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .collect();
        
        if filtered.len() > 3 { // Filter short junk
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
    filter: &str
) -> (String, Vec<String>) {
    let mut final_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    final_args.push("-i".to_string());
    final_args.push(interface.to_string());
    final_args.push("-l".to_string());

    if !filter.is_empty() {
        final_args.push(filter.to_string());
    }

    (base_cmd.to_string(), final_args)
}

#[cfg(test)]
#[path = "sniffer_tests.rs"]
mod tests;
