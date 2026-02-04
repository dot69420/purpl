use crate::io_handler::IoHandler;
use colored::*;
use roxmltree::Document;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct ServiceInfo {
    pub port: String,
    pub protocol: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug)]
pub struct HostInfo {
    pub ip_v4: Option<String>,
    pub ip_v6: Option<String>,
    pub mac: Option<String>,
    pub os_name: Option<String>,
    pub services: Vec<ServiceInfo>,
}

#[derive(Deserialize, Debug)]
pub struct WifiteReport {
    pub bssid: String,
    pub essid: String,
    pub key: Option<String>,
    pub encryption: Option<String>,
}

pub fn display_scan_report(scan_dir: &Path, io: &dyn IoHandler) {
    io.println(&format!(
        "{}",
        format!("\n--- Report for: {} ---", scan_dir.display())
            .blue()
            .bold()
    ));
    let mut any_report_found = false;

    // 1. Look for Nmap XML files
    if let Ok(entries) = fs::read_dir(scan_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "xml" {
                    let content = match fs::read_to_string(&path) {
                        Ok(c) => c,
                        Err(e) => {
                            io.println(&format!(
                                "{}",
                                format!("[!] Failed to read file: {}", e).red()
                            ));
                            continue;
                        }
                    };
                    io.println(&format!(
                        "{}",
                        format!(
                            "\nParsing Nmap Report: {}",
                            path.file_name().unwrap().to_string_lossy()
                        )
                        .cyan()
                    ));
                    let hosts = parse_nmap_xml(&content, io);
                    print_nmap_hosts(hosts, io);
                    any_report_found = true;
                }
            }
        }
    }

    // 2. Look for Wifite cracked.json
    // Check local 'cracked.json' (if moved correctly)
    let wifite_path = scan_dir.join("hs/cracked.json"); // wifite usually puts it in hs/ inside the dir if we moved the whole hs folder
    let wifite_path_root = scan_dir.join("cracked.json"); // or just at root

    let wifite_final_path = if wifite_path.exists() {
        Some(wifite_path)
    } else if wifite_path_root.exists() {
        Some(wifite_path_root)
    } else {
        None
    };

    if let Some(path) = wifite_final_path {
        io.println(&format!(
            "{}",
            format!("\nParsing Wifite Report: {}", path.display()).cyan()
        ));
        match fs::read_to_string(&path) {
            Ok(content) => {
                let entries = parse_wifite_json(&content, io);
                print_wifite_report(entries, io);
                any_report_found = true;
            }
            Err(e) => {
                io.println(&format!(
                    "{}",
                    format!("[!] Failed to read file: {}", e).red()
                ));
            }
        }
    }

    // 3. Look for Sniffer Report (report.txt)
    let sniffer_report = scan_dir.join("report.txt");
    if sniffer_report.exists() {
        print_text_report(&sniffer_report, io, "Packet Sniffer Report");
        any_report_found = true;
    }

    // 4. Look for Bluetooth/Generic Scan (scan.txt)
    let generic_scan = scan_dir.join("scan.txt");
    if generic_scan.exists() {
        print_text_report(&generic_scan, io, "Bluetooth/Generic Scan Report");
        any_report_found = true;
    }

    // 5. Look for Gobuster Report (gobuster.txt)
    let gobuster_scan = scan_dir.join("gobuster.txt");
    if gobuster_scan.exists() {
        print_gobuster_report(&gobuster_scan, io);
        any_report_found = true;
    }

    // 6. Look for Hydra Report (hydra.txt)
    let hydra_scan = scan_dir.join("hydra.txt");
    if hydra_scan.exists() {
        print_hydra_report(&hydra_scan, io);
        any_report_found = true;
    }

    // 7. Look for Ffuf Report (ffuf.json)
    let ffuf_scan = scan_dir.join("ffuf.json");
    if ffuf_scan.exists() {
        print_text_report(&ffuf_scan, io, "Fuzzing Report (JSON)");
        any_report_found = true;
    }

    // 8. Look for Host Discovery (host_discovery.txt)
    let host_disc = scan_dir.join("host_discovery.txt");
    if host_disc.exists() {
        print_text_report(&host_disc, io, "Host Discovery Log");
        any_report_found = true;
    }

    if !any_report_found {
        io.println(&format!("{}", "No recognized report files (Nmap XML, Wifite JSON, Gobuster, Hydra, Sniffer/Generic TXT) found in this directory.".yellow()));
    }
}

fn print_text_report(path: &Path, io: &dyn IoHandler, title: &str) {
    io.println(&format!(
        "{}",
        format!(
            "\nReading {}: {}",
            title,
            path.file_name().unwrap().to_string_lossy()
        )
        .magenta()
    ));
    io.println(&"-".repeat(60));

    match fs::read_to_string(path) {
        Ok(content) => {
            io.println(&content);
        }
        Err(e) => io.println(&format!(
            "{} {}",
            "[!] Failed to read report file:".red(),
            e
        )),
    }
}

fn print_gobuster_report(path: &Path, io: &dyn IoHandler) {
    io.println(&format!(
        "{}",
        format!(
            "\nParsing Web Enumeration Report: {}",
            path.file_name().unwrap().to_string_lossy()
        )
        .cyan()
    ));
    io.println(&"-".repeat(60));

    match fs::read_to_string(path) {
        Ok(content) => {
            for line in content.lines() {
                if line.contains("(Status: 200)") {
                    io.println(&format!("{}", line.green().bold()));
                } else if line.contains("(Status: 301)") || line.contains("(Status: 302)") {
                    io.println(&format!("{}", line.blue()));
                } else if line.contains("(Status: 403)") || line.contains("(Status: 401)") {
                    io.println(&format!("{}", line.yellow()));
                } else {
                    io.println(line);
                }
            }
        }
        Err(e) => io.println(&format!("{} {}", "[!] Failed to read file:".red(), e)),
    }
}

fn print_hydra_report(path: &Path, io: &dyn IoHandler) {
    io.println(&format!(
        "{}",
        format!(
            "\nParsing Credential Access Report: {}",
            path.file_name().unwrap().to_string_lossy()
        )
        .red()
        .bold()
    ));
    io.println(&"-".repeat(60));

    match fs::read_to_string(path) {
        Ok(content) => {
            if content.trim().is_empty() {
                io.println(&format!("{}", "[-] No credentials found in file.".yellow()));
                return;
            }

            for line in content.lines() {
                // Hydra output format usually contains "login:" and "password:"
                if line.contains("login:") && line.contains("password:") {
                    io.println(&format!(
                        "  {} {}",
                        "[CRACKED]".red().bold().blink(),
                        line.green()
                    ));
                } else {
                    io.println(line);
                }
            }
        }
        Err(e) => io.println(&format!("{} {}", "[!] Failed to read file:".red(), e)),
    }
}

pub fn parse_nmap_xml(content: &str, io: &dyn IoHandler) -> Vec<HostInfo> {
    let doc = match Document::parse(content) {
        Ok(d) => d,
        Err(e) => {
            io.println(&format!(
                "{}",
                format!("[!] Failed to parse XML: {}", e).red()
            ));
            return Vec::new();
        }
    };

    let mut hosts = Vec::new();

    for host_node in doc.descendants().filter(|n| n.has_tag_name("host")) {
        let mut host = HostInfo {
            ip_v4: None,
            ip_v6: None,
            mac: None,
            os_name: None,
            services: Vec::new(),
        };

        // Iterate over children once to avoid multiple descendant traversals
        for child in host_node.children() {
            if child.has_tag_name("address") {
                let addr_str = child.attribute("addr").unwrap_or_default().to_string();
                match child.attribute("addrtype") {
                    Some("ipv4") => host.ip_v4 = Some(addr_str),
                    Some("ipv6") => host.ip_v6 = Some(addr_str),
                    Some("mac") => host.mac = Some(addr_str),
                    _ => {}
                }
            } else if child.has_tag_name("os") {
                if host.os_name.is_none() {
                    if let Some(os) = child.children().find(|n| n.has_tag_name("osmatch")) {
                        host.os_name = os.attribute("name").map(|s| s.to_string());
                    }
                }
            } else if child.has_tag_name("ports") {
                for port in child.children().filter(|n| n.has_tag_name("port")) {
                    let port_id = port.attribute("portid").unwrap_or("?").to_string();
                    let protocol = port.attribute("protocol").unwrap_or("?").to_string();

                    let mut service_name = String::from("unknown");
                    let mut service_version = String::new();

                    if let Some(service) = port.children().find(|n| n.has_tag_name("service")) {
                        service_name = service.attribute("name").unwrap_or("unknown").to_string();
                        let product = service.attribute("product").unwrap_or("");
                        let version = service.attribute("version").unwrap_or("");
                        if !product.is_empty() || !version.is_empty() {
                            service_version = format!("{} {}", product, version).trim().to_string();
                        }
                    }

                    host.services.push(ServiceInfo {
                        port: port_id,
                        protocol,
                        name: service_name,
                        version: service_version,
                    });

                    // Check for Scripts (Vulnerabilities)
                    for script in port.children().filter(|n| n.has_tag_name("script")) {
                        let id = script.attribute("id").unwrap_or("script");
                        let output = script.attribute("output").unwrap_or("");
                        if !output.is_empty() {
                            io.println(&format!(
                                "  {} [{}]:",
                                "  [!] Vulnerability/Script Found".red().bold(),
                                id.yellow()
                            ));
                            for line in output.lines() {
                                io.println(&format!("      {}", line.dimmed()));
                            }
                        }
                    }
                }
            }
        }
        hosts.push(host);
    }
    hosts
}

pub fn print_nmap_hosts(hosts: Vec<HostInfo>, io: &dyn IoHandler) {
    for host in hosts {
        // Display Host Info
        io.println(&"-".repeat(50));
        if let Some(ip) = &host.ip_v4 {
            io.println(&format!("IPv4: {}", ip.green().bold()));
        }
        if let Some(ip) = &host.ip_v6 {
            io.println(&format!("IPv6: {}", ip.green().bold()));
        }
        if let Some(mac) = &host.mac {
            io.println(&format!("MAC:  {}", mac.yellow()));
        }
        if let Some(os) = &host.os_name {
            io.println(&format!("OS:   {}", os.cyan()));
        }

        if !host.services.is_empty() {
            io.println(&format!(
                "\n  {:<10} | {:<20} | {:<30}",
                "PORT", "SERVICE", "VERSION"
            ));
            io.println(&format!("  {}", "-".repeat(65)));
            for svc in host.services {
                io.println(&format!(
                    "  {:<10} | {:<20} | {:<30}",
                    format!("{}/{}", svc.port, svc.protocol),
                    svc.name,
                    svc.version
                ));
                // External Link for more info
                if !svc.name.is_empty() && svc.name != "unknown" {
                    let query = format!("{} {} exploit", svc.name, svc.version);
                    let url = format!(
                        "https://www.google.com/search?q={}",
                        query.replace(" ", "+")
                    );
                    io.println(&format!("  {}: {}", "-> Info".blue().italic(), url));
                }
            }
        }
        io.println("");
    }
}

pub fn parse_wifite_json(content: &str, io: &dyn IoHandler) -> Vec<WifiteReport> {
    match serde_json::from_str::<Vec<WifiteReport>>(content) {
        Ok(e) => e,
        Err(_) => {
            io.println(&format!(
                "{}",
                "[!] Could not parse cracked.json structure.".yellow()
            ));
            Vec::new()
        }
    }
}

pub fn print_wifite_report(entries: Vec<WifiteReport>, io: &dyn IoHandler) {
    if entries.is_empty() {
        io.println("No cracked networks found in report.");
        return;
    }

    io.println(&format!(
        "{:<20} | {:<15} | {:<10} | {:<20}",
        "ESSID", "BSSID", "ENC", "KEY"
    ));
    io.println(&"-".repeat(70));
    for entry in entries {
        io.println(&format!(
            "{:<20} | {:<15} | {:<10} | {:<20}",
            entry.essid.green(),
            entry.bssid,
            entry
                .encryption
                .clone()
                .unwrap_or_else(|| "???".to_string())
                .yellow(),
            entry
                .key
                .clone()
                .unwrap_or_else(|| "N/A".to_string())
                .red()
                .bold()
        ));
    }
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;
