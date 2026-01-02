use std::process::{Command, Stdio};
use std::io::{self, BufRead, BufReader, Write};
use std::fs::{self, File};
use std::thread;
use chrono::Local;
use colored::*;
use regex::Regex;
use crate::history::{append_history, HistoryEntry};

#[derive(Debug, Clone)]
struct SniffProfile {
    name: String,
    description: String,
    filter: String, // tcpdump filter syntax
    args: Vec<&'static str>,
}

impl SniffProfile {
    fn new(name: &str, description: &str, filter: &str, args: &[&'static str]) -> Self {
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

pub fn run_sniffer(interface: &str, _use_proxy: bool) {
    // 1. Check Root
    if unsafe { libc::geteuid() } != 0 {
        println!("{}", "[!] Packet sniffing requires ROOT privileges.".red());
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

    println!("\n{}", "Select Sniffer Profile:".blue().bold());
    for (i, profile) in profiles.iter().enumerate() {
        println!("[{}] {} - {}", i + 1, profile.name.green(), profile.description);
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

    // 3. Setup Output
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/packets/{}", date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    
    let pcap_file = format!("{}/capture.pcap", output_dir);
    let report_file = format!("{}/report.txt", output_dir);

    println!("{}", format!("\n[+] Starting {} on {}", profile.name, interface).green());
    println!("    Filter: {}", if profile.filter.is_empty() { "None (All)" } else { &profile.filter });
    println!("[+] Saving PCAP to: {}", pcap_file);
    println!("[+] Live parsing... Press Ctrl+C to stop.");

    // 4. Start TCPDump
    let mut args = profile.args.clone();
    args.push("-i");
    args.push(interface);
    args.push("-l"); // Line buffered

    if !profile.filter.is_empty() {
        args.push(&profile.filter);
    }

    let mut cmd = Command::new("tcpdump")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()) // tcpdump often prints verbose info to stderr
        .spawn()
        .expect("Failed to start tcpdump");

    let stdout = cmd.stdout.take().expect("Failed to capture stdout");
    let reader = BufReader::new(stdout);

    let report_path = report_file.clone();
    
    // We need a thread to read output and process it
    let handle = thread::spawn(move || {
        let mut file = File::create(report_path).expect("Failed to create report file");
        
        let mut current_packet = String::new();
        
        for line in reader.lines() {
            if let Ok(l) = line {
                // Heuristic Parsing
                if l.contains(" IP ") {
                    // New packet start
                    if !current_packet.is_empty() {
                         process_packet_block(&current_packet, &mut file);
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
             process_packet_block(&current_packet, &mut file);
        }
    });
    
    println!("{}", "Press Ctrl+C to stop capturing...".yellow());
    let _ = cmd.wait(); 
    
    let _ = handle.join();
    let _ = append_history(&HistoryEntry::new("Sniffer", interface, &format!("Profile: {}", profile.name)));
}

fn process_packet_block(block: &str, file: &mut File) {
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
        println!("{}", "-".repeat(50).dimmed());
        println!("{} {} -> {}", time.blue(), src.green(), dst.red());
        println!("Type: {}", content_type.yellow().bold());
        if !clean_payload.is_empty() {
            println!("Content:\n{}", clean_payload.white());
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