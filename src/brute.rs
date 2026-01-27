use std::path::{Path, PathBuf};
use std::fs;
use chrono::Local;
use colored::*;
use crate::history::{append_history, HistoryEntry};
use crate::executor::CommandExecutor;
use crate::io_handler::IoHandler;
use crate::nmap;
use crate::report;

#[derive(Debug, Clone)]
pub struct BruteProfile {
    pub name: String,
    pub description: String,
    pub userlist: String,
    pub passlist: String,
    pub flags: Vec<&'static str>,
}

impl BruteProfile {
    pub fn new(name: &str, description: &str, userlist: &str, passlist: &str, flags: &[&'static str]) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            userlist: userlist.to_string(),
            passlist: passlist.to_string(),
            flags: flags.to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BruteConfig {
    pub target: String,
    pub protocol: String,
    pub port: String,
    pub profile: BruteProfile,
}

pub fn configure_brute_force(target_input: &str, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) -> Option<BruteConfig> {
    // 1. Check dependency
    if executor.execute_output("hydra", &["-h"]).is_err() {
        io.println(&format!("{}", "[-] 'hydra' not found. Please install it (sudo pacman -S hydra).".red()));
        return None;
    }

    io.println(&format!("\n{}", "--- Credential Access Module (Hydra) ---".red().bold()));

    // 2. Select Target
    let final_target = if target_input.is_empty() {
        if let Some(t) = select_target_or_scan(use_proxy, executor, io) {
            io.println(&format!("{} {}", "[*] Target set to:".blue(), t.yellow().bold()));
            t
        } else {
            return None;
        }
    } else {
        target_input.to_string()
    };

    // 3. Detect Services
    let detected_services = detect_services(&final_target, io);
    let selected_protocol;
    let selected_port;

    if !detected_services.is_empty() {
        io.println(&format!("\n{}", "Detected Services (from Nmap):".green().bold()));
        for (i, svc) in detected_services.iter().enumerate() {
            io.println(&format!("[{}] {} ({}/{}) - {}", i + 1, svc.name, svc.port, svc.protocol, svc.version));
        }
        io.println(&format!("[{}] Manual Protocol Selection", detected_services.len() + 1));

        io.print("\nSelect target service: ");
        io.flush();
        let input = io.read_line();
        if let Ok(idx) = input.trim().parse::<usize>() {
            if idx > 0 && idx <= detected_services.len() {
                let svc = &detected_services[idx - 1];
                selected_protocol = svc.name.clone();
                selected_port = svc.port.clone();
            } else {
                // Manual selection fallback
                 selected_protocol = manual_protocol_selection(io);
                 selected_port = "22".to_string(); // Default port for manual fallback logic simplification
            }
        } else {
             // Default or invalid
             selected_protocol = manual_protocol_selection(io);
             selected_port = "22".to_string();
        }
    } else {
        io.println(&format!("\n{}", "[-] No Nmap data found. Proceeding with manual selection.".dimmed()));
        selected_protocol = manual_protocol_selection(io);
        selected_port = "22".to_string(); // Default
    }

    // 4. Resolve Wordlists
    // Common Usernames
    let user_list_path = find_wordlist(&[
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/metasploit/unix_users.txt",
        "wordlists/users.txt"
    ]).unwrap_or_else(|| "manual".to_string());

    // Common Passwords
    let pass_list_path = find_wordlist(&[
        "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
        "/usr/share/wordlists/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt", // Good for quick spray
        "/usr/share/wordlists/metasploit/unix_passwords.txt", 
        "wordlists/passwords.txt"
    ]).unwrap_or_else(|| "manual".to_string());

    // 5. Define Profiles
    let mut profiles = Vec::new();

    if user_list_path != "manual" && pass_list_path != "manual" {
        profiles.push(BruteProfile::new(
            "Quick Spray",
            "Top usernames vs Top passwords. Fast check for weak creds.",
            &user_list_path,
            &pass_list_path,
            &["-t", "4", "-I"] // -I to ignore existing restore file
        ));
    }

    profiles.push(BruteProfile::new(
        "Single User / Spray",
        "Target one specific user (e.g., 'root') with a password list.",
        "input", // placeholder
        &pass_list_path,
        &["-t", "4"]
    ));

    profiles.push(BruteProfile::new(
        "Custom / Manual",
        "Select your own lists.",
        "manual",
        "manual",
        &["-t", "4"]
    ));

    // 6. Select Profile
    io.println(&format!("\n{}", "Select Attack Profile:".blue().bold()));
    for (i, p) in profiles.iter().enumerate() {
        io.println(&format!("[{}] {} - {}", i + 1, p.name.green(), p.description));
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

    // Handle Input/Manual
    if selected_profile.name.contains("Single User") {
        io.print(&format!("{}", "Enter Username to target: ".yellow()));
        io.flush();
        let user = io.read_line();
        selected_profile.userlist = user.trim().to_string();
    } else if selected_profile.userlist == "manual" {
         io.print(&format!("{}", "Enter path to USER list: ".yellow()));
         io.flush();
         let path = io.read_line();
         selected_profile.userlist = path.trim().to_string();
    } 

    if selected_profile.passlist == "manual" {
         io.print(&format!("{}", "Enter path to PASSWORD list: ".yellow()));
         io.flush();
         let path = io.read_line();
         selected_profile.passlist = path.trim().to_string();
    }

    Some(BruteConfig {
        target: final_target,
        protocol: selected_protocol,
        port: selected_port,
        profile: selected_profile,
    })
}

pub fn execute_brute_force(config: BruteConfig, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // 7. Setup Output
    let safe_target = config.target.replace("://", "_").replace('/', "_");
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/brute/{}/{}", safe_target, date);
    fs::create_dir_all(&output_dir).expect("Failed to create output dir");
    let output_file = format!("{}/hydra.txt", output_dir);

    // If port differs from default, append it to protocol
    let protocol_str = if !config.port.is_empty() && is_non_standard_port(&config.protocol, &config.port) {
         format!("{}://{}:{}", config.protocol, config.target, config.port)
    } else {
         format!("{}://{}", config.protocol, config.target)
    };
    
    io.println(&format!("{}", format!("\n[+] Starting Hydra on {}", protocol_str).green()));
    io.println(&format!("[+] Saving output to: {}", output_file));

    let user_arg = if config.profile.name.contains("Single User") { "-l".to_string() } else { "-L".to_string() };
    let pass_arg = "-P".to_string();

    // 8. Execute
    let (final_cmd, final_args) = build_hydra_command(
        "hydra",
        &config.profile.flags,
        &user_arg,
        &config.profile.userlist,
        &pass_arg,
        &config.profile.passlist,
        &output_file,
        &config.target,
        &config.protocol,
        &config.port,
        use_proxy
    );
    let final_args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();

    let status = executor.execute(&final_cmd, &final_args_str);

    match status {
        Ok(s) => {
            if s.success() {
                if let Ok(content) = fs::read_to_string(&output_file) {
                    if !content.trim().is_empty() {
                         io.println(&format!("{}", "\n[+] Credentials Found!".green().bold()));
                         io.println(&content);
                         let _ = append_history(&HistoryEntry::new("BruteForce", &config.target, "CRACKED"));
                    } else {
                         io.println(&format!("{}", "\n[-] No credentials found.".yellow()));
                         let _ = append_history(&HistoryEntry::new("BruteForce", &config.target, "Failed"));
                    }
                }
            } else {
                io.println(&format!("{}", "\n[!] Hydra failed or was interrupted.".yellow()));
            }
        },
        Err(e) => io.println(&format!("{} {}", "[!] Failed to start process:".red(), e)),
    }
}

// Backward compatibility wrapper
pub fn run_brute_force(target_input: &str, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    if let Some(config) = configure_brute_force(target_input, use_proxy, executor, io) {
        execute_brute_force(config, use_proxy, executor, io);
    }
}

fn select_target_or_scan(use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) -> Option<String> {
    let nmap_dir = Path::new("scans").join("nmap");
    let mut targets: Vec<String> = Vec::new();

    if nmap_dir.exists() {
        if let Ok(entries) = fs::read_dir(nmap_dir) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() {
                        if let Ok(name) = entry.file_name().into_string() {
                             targets.push(name);
                        }
                    }
                }
            }
        }
    }
    targets.sort();

    io.println(&format!("\n{}", "Target Selection:".cyan().bold()));
    if targets.is_empty() {
        io.println(&format!("{}", "  (No previous Nmap scans found)".dimmed()));
    } else {
        for (i, t) in targets.iter().enumerate() {
            io.println(&format!("[{}] {}", i + 1, t));
        }
    }

    let scan_option_idx = targets.len() + 1;
    let manual_option_idx = targets.len() + 2;

    io.println(&format!("[{}] {}", scan_option_idx, "New Target (Run Nmap Scan first)".green()));
    io.println(&format!("[{}] {}", manual_option_idx, "New Target (Manual Input)".yellow()));
    io.println("[0] Back");

    io.print("\nSelect option: ");
    io.flush();
    let input = io.read_line();
    let choice = input.trim().parse::<usize>().unwrap_or(999);

    if choice == 0 { return None; }

    if choice > 0 && choice <= targets.len() {
        return Some(targets[choice - 1].clone());
    } else if choice == scan_option_idx {
        io.print("\nEnter Target IP for Scan: ");
        io.flush();
        let new_target = io.read_line().trim().to_string();
        if new_target.is_empty() { return None; }
        
        io.println(&format!("{}", "\n[+] Redirecting to Network Scan module...".blue()));
        nmap::run_nmap_scan(&new_target, None, false, None, use_proxy, executor, io);
        return Some(new_target);
    } else if choice == manual_option_idx {
        io.print("Enter Target IP: ");
        io.flush();
        let manual = io.read_line().trim().to_string();
        if manual.is_empty() { return None; }
        return Some(manual);
    }

    io.println(&format!("{}", "[!] Invalid selection.".red()));
    None
}

fn detect_services(target: &str, io: &dyn IoHandler) -> Vec<report::ServiceInfo> {
    // 1. Resolve XML path (reusing logic conceptually, but implementing simply)
    // Try scans/nmap/<target>/nmap.xml (standard path)
    // Or iterate directories if needed, but standard path is best.
    let target_safe = target.replace('/', "_");
    let scan_dir = Path::new("scans").join("nmap").join(&target_safe);

    if !scan_dir.exists() { return Vec::new(); }

    // Find XML
    let mut xml_path: Option<PathBuf> = None;
    if let Ok(entries) = fs::read_dir(&scan_dir) {
        for entry in entries.flatten() {
            if entry.path().extension().map_or(false, |e| e == "xml") {
                xml_path = Some(entry.path());
                break;
            }
        }
    }

    if let Some(path) = xml_path {
        if let Ok(content) = fs::read_to_string(path) {
             let hosts = report::parse_nmap_xml(&content, io);
             // Flatten services from all hosts (usually just one)
             let mut all_services = Vec::new();
             for h in hosts {
                 for s in h.services {
                     if !s.name.is_empty() && s.name != "unknown" {
                         all_services.push(s);
                     }
                 }
             }
             return all_services;
        }
    }
    Vec::new()
}

fn manual_protocol_selection(io: &dyn IoHandler) -> String {
    io.println(&format!("\n{}", "Select Target Protocol:".blue().bold()));
    let protocols = vec!["ssh", "ftp", "telnet", "rdp", "mysql", "postgresql", "smb", "http-get", "http-post-form"];
    for (i, p) in protocols.iter().enumerate() {
        io.println(&format!("[{}] {}", i + 1, p));
    }
    
    io.print(&format!("\nChoose protocol [1-{}]: ", protocols.len()));
    io.flush();
    let p_in = io.read_line();
    
    if let Ok(idx) = p_in.trim().parse::<usize>() {
        if idx > 0 && idx <= protocols.len() {
            protocols[idx - 1].to_string()
        } else {
            "ssh".to_string()
        }
    } else {
        "ssh".to_string()
    }
}

// Helper to check if port is non-standard for protocol
fn is_non_standard_port(proto: &str, port: &str) -> bool {
    match proto {
        "ssh" => port != "22",
        "ftp" => port != "21",
        "telnet" => port != "23",
        "http" | "http-get" => port != "80",
        "https" => port != "443",
        "rdp" => port != "3389",
        "mysql" => port != "3306",
        "postgresql" => port != "5432",
        _ => true
    }
}

fn find_wordlist(candidates: &[&str]) -> Option<String> {
    for path in candidates {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }
    None
}

pub fn build_hydra_command(
    base_cmd: &str,
    flags: &[&str],
    user_arg: &str,
    userlist: &str,
    pass_arg: &str,
    passlist: &str,
    output_file: &str,
    target: &str,
    protocol: &str,
    port: &str,
    use_proxy: bool
) -> (String, Vec<String>) {
    let mut cmd_args: Vec<String> = flags.iter().map(|s| s.to_string()).collect();

    cmd_args.push(user_arg.to_string());
    cmd_args.push(userlist.to_string());

    cmd_args.push(pass_arg.to_string());
    cmd_args.push(passlist.to_string());

    cmd_args.push("-o".to_string());
    cmd_args.push(output_file.to_string());
    
    // Port argument
    if !port.is_empty() && is_non_standard_port(protocol, port) {
        cmd_args.push("-s".to_string());
        cmd_args.push(port.to_string());
    }

    cmd_args.push(target.to_string());
    cmd_args.push(protocol.to_string());

    let mut final_cmd = base_cmd.to_string();
    let mut final_args = cmd_args;

    if use_proxy {
        final_args.insert(0, final_cmd);
        final_cmd = "proxychains".to_string();
    }

    (final_cmd, final_args)
}

#[cfg(test)]
#[path = "brute_tests.rs"]
mod tests;
