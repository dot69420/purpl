use std::fs;
use std::path::Path;
use colored::*;
use roxmltree::Document;
use serde::Deserialize;

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

// Wifite cracked.json structure (approximate)
#[derive(Deserialize, Debug)]
struct WifiteEntry {
    bssid: String,
    essid: String,
    key: Option<String>,
    encryption: Option<String>,
}

#[derive(Deserialize, Debug)]
struct WifiteReport {
    // Wifite often outputs a list of objects or a dict. 
    // We'll try to parse a list of entries.
    // If wifite structure is different, we might need to adjust.
    // For now, let's assume standard JSON array of objects if we can find documentation or valid output.
    // Actually, wifite usually produces a 'cracked.json' which is a list.
}

pub fn display_scan_report(scan_dir: &Path) {
    println!("{}", format!("\n--- Report for: {} ---", scan_dir.display()).blue().bold());

    // 1. Look for Nmap XML files
    let mut nmap_found = false;
    if let Ok(entries) = fs::read_dir(scan_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "xml" {
                    parse_and_print_nmap(&path);
                    nmap_found = true;
                }
            }
        }
    }

    if !nmap_found {
        println!("{}", "No Nmap XML report found in this directory.".yellow());
    }

    // 2. Look for Wifite cracked.json (usually in hs/ or root of scan dir if moved)
    // Note: Wifite saves to 'hs/cracked.json' usually relative to where it ran.
    // Since we run wifite in the tool, we might need to track where it puts files.
    // For now, let's check if 'hs/cracked.json' exists in the current directory or the scan dir.
    
    // Check specific known locations for wifite logs if mapped to this scan
    let wifite_path = scan_dir.join("cracked.json");
    if wifite_path.exists() {
        parse_and_print_wifite(&wifite_path);
    } else {
        // Fallback: check global 'hs/cracked.json' just in case user ran it recently
        let global_wifite = Path::new("hs/cracked.json");
        if global_wifite.exists() {
             println!("\n{}", "Found global Wifite cracked.json (might be unrelated to this specific scan dir):".yellow());
             parse_and_print_wifite(global_wifite);
        }
    }
}

fn parse_and_print_nmap(path: &Path) {
    println!("{}", format!("\nParsing Nmap Report: {}", path.file_name().unwrap().to_string_lossy()).cyan());
    
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            println!("{}", format!("[!] Failed to read file: {}", e).red());
            return;
        }
    };

    let doc = match Document::parse(&content) {
        Ok(d) => d,
        Err(e) => {
            println!("{}", format!("[!] Failed to parse XML: {}", e).red());
            return;
        }
    };

    for host_node in doc.descendants().filter(|n| n.has_tag_name("host")) {
        let mut host = HostInfo {
            ip_v4: None,
            ip_v6: None,
            mac: None,
            os_name: None,
            services: Vec::new(),
        };

        // Addresses
        for addr in host_node.children().filter(|n| n.has_tag_name("address")) {
            let addr_str = addr.attribute("addr").unwrap_or_default().to_string();
            match addr.attribute("addrtype") {
                Some("ipv4") => host.ip_v4 = Some(addr_str),
                Some("ipv6") => host.ip_v6 = Some(addr_str),
                Some("mac") => host.mac = Some(addr_str),
                _ => {}
            }
        }

        // OS
        if let Some(os) = host_node.descendants().find(|n| n.has_tag_name("osmatch")) {
            host.os_name = os.attribute("name").map(|s| s.to_string());
        }

        // Services
        if let Some(ports) = host_node.descendants().find(|n| n.has_tag_name("ports")) {
            for port in ports.children().filter(|n| n.has_tag_name("port")) {
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
            }
        }

        // Display Host Info
        println!("{}", "-".repeat(50));
        if let Some(ip) = &host.ip_v4 { println!("IPv4: {}", ip.green().bold()); }
        if let Some(ip) = &host.ip_v6 { println!("IPv6: {}", ip.green().bold()); }
        if let Some(mac) = &host.mac { println!("MAC:  {}", mac.yellow()); }
        if let Some(os) = &host.os_name { println!("OS:   {}", os.cyan()); }

        if !host.services.is_empty() {
            println!("\n  {:<10} | {:<20} | {:<30}", "PORT", "SERVICE", "VERSION");
            println!("  {}", "-".repeat(65));
            for svc in host.services {
                println!("  {:<10} | {:<20} | {:<30}", 
                    format!("{}/{}", svc.port, svc.protocol), 
                    svc.name, 
                    svc.version
                );
                // External Link for more info
                if !svc.name.is_empty() && svc.name != "unknown" {
                    let query = format!("{} {} exploit", svc.name, svc.version);
                    let url = format!("https://www.google.com/search?q={}", query.replace(" ", "+"));
                    println!("  {}: {}", "-> Info".blue().italic(), url);
                }
            }
        }
        println!();
    }
}

fn parse_and_print_wifite(path: &Path) {
    println!("{}", format!("\nParsing Wifite Report: {}", path.display()).cyan());
    
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            println!("{}", format!("[!] Failed to read file: {}", e).red());
            return;
        }
    };

    // Wifite cracked.json is usually a list of objects
    let entries: Vec<WifiteEntry> = match serde_json::from_str(&content) {
        Ok(e) => e,
        Err(_) => {
            println!("{}", "[!] Could not parse cracked.json structure.".yellow());
            return;
        }
    };

    if entries.is_empty() {
        println!("No cracked networks found in report.");
        return;
    }

    println!("{:<20} | {:<20} | {:<20}", "ESSID", "BSSID", "KEY");
    println!("{}", "-".repeat(65));
    for entry in entries {
        println!("{:<20} | {:<20} | {:<20}", 
            entry.essid.green(), 
            entry.bssid, 
            entry.key.unwrap_or_else(|| "N/A".to_string()).red().bold()
        );
    }
}
