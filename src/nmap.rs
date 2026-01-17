use std::fs;

use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use colored::*;
use crate::history::{append_history, HistoryEntry};
use crate::executor::CommandExecutor;
use crate::io_handler::IoHandler;

#[derive(Debug)]
pub struct ScanProfile {
    pub name: String,
    pub description: String,
    pub flags: Vec<&'static str>,
    pub requires_root: bool,
}

impl ScanProfile {
    fn new(name: &str, description: &str, flags: &[&'static str], requires_root: bool) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            flags: flags.to_vec(),
            requires_root,
        }
    }
}

fn select_scan_profile(is_large_network: bool, io: &dyn IoHandler) -> ScanProfile {
    if is_large_network {
         io.println(&format!("\n{}", "[!] Large Network Detected (Class A /8)".yellow().bold()));
         io.println("Auto-selecting 'Mass Scan' profile to prevent timeout/hanging.");
         return ScanProfile::new(
             "Mass Scan",
             "Optimized for large networks (No DNS, aggressive timing, rate limited)",
             &["-sS", "-sV", "-O", "-T4", "--max-retries", "1", "--version-light", "-n", "--min-rate", "1000"],
             true
         );
    }

    io.println(&format!("\n{}", "Select Scan Profile:".blue().bold()));
    let profiles = vec![
        ScanProfile::new(
            "Stealth & Vuln",
            "Default. TCP SYN scan + Service/OS detection + Vulnerability scripts. (Balanced) [ROOT]",
            &["-sS", "-sV", "-O", "--script", "vuln", "-T3", "--version-intensity", "5"],
            true
        ),
        ScanProfile::new(
            "Connect Scan",
            "Non-root friendly. Uses full TCP handshake. Detects open ports/services. [NON-ROOT]",
            &["-sT", "-sV", "--version-intensity", "5"],
            false
        ),
        ScanProfile::new(
            "Quick Audit",
            "Fast scan. Top 100 ports + Version detection. Good for quick triage. [ROOT]",
            &["-sS", "-sV", "--top-ports", "100", "-T4"],
            true
        ),
        ScanProfile::new(
            "Intense Scan",
            "Very aggressive. All ports, OS, Service, Scripts, Traceroute. (Noisy & Slow) [ROOT]",
            &["-sS", "-sV", "-O", "-p-", "--script", "default,vuln", "-A", "-T4"],
            true
        ),
        ScanProfile::new(
            "Paranoid (Evasion)",
            "Slow timing to evade IDS/Firewalls. Very stealthy but takes a long time. [ROOT]",
            &["-sS", "-sV", "-T1", "-f", "--mtu", "24"],
            true
        ),
    ];

    for (i, profile) in profiles.iter().enumerate() {
        io.println(&format!("[{}] {} - {}", i + 1, profile.name.green(), profile.description));
    }

    let input = io.read_input(&format!("\nChoose a profile [1-{}]", profiles.len()), Some("1"));

    if let Ok(idx) = input.trim().parse::<usize>() {
        if idx > 0 && idx <= profiles.len() {
            let p = &profiles[idx - 1];
            return ScanProfile::new(&p.name, &p.description, &p.flags, p.requires_root);
        }
    }

    io.println(&format!("{}", "[!] Invalid selection. Defaulting to 'Stealth & Vuln'.".yellow()));
    ScanProfile::new(
        "Stealth & Vuln",
        "Default. TCP SYN scan + Service/OS detection + Vulnerability scripts. (Balanced)",
        &["-sS", "-sV", "-O", "--script", "vuln", "-T3", "--version-intensity", "5"],
        true
    )
}

pub fn run_nmap_scan(target: &str, custom_ports: Option<&str>, skip_discovery: bool, extra_args: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    let is_root = executor.is_root();

    if use_proxy {
        io.println(&format!("{}", "[*] Proxychains Enabled. Traffic will be routed through configured proxies.".magenta().bold()));
    }

    if target.ends_with("/8") {
        io.println(&format!("{}", "[!] Warning: Class A scan detected.".yellow()));
    }

    // Select Profile
    let is_large_network = target.ends_with("/8");
    
    let mut profile = if let Some(ports) = custom_ports {
        io.println(&format!("{}", format!("[+] Custom Port Mode: Scanning ports '{}'", ports).cyan()));
        ScanProfile::new(
            "Custom Port Scan",
            "User specified ports.",
            &["-sV", "-T4"], // Base flags
            false 
        )
    } else {
        select_scan_profile(is_large_network, io)
    };

    // Convert profile flags to Vec<String> so we can mutate them
    let mut profile_flags: Vec<String> = profile.flags.iter().map(|s| s.to_string()).collect();

    // Apply Custom Ports
    if let Some(ports) = custom_ports {
        profile_flags.push("-p".to_string());
        profile_flags.push(ports.to_string());
    }

    // Apply Skip Discovery (-Pn) to Deep Scan flags as well
    if skip_discovery {
        profile_flags.push("-Pn".to_string());
    }

    // Apply Extra Args to Deep Scan
    if let Some(extras) = extra_args {
         for arg in extras.split_whitespace() {
             profile_flags.push(arg.to_string());
         }
    }

    let mut use_sudo = false;

    if profile.requires_root && !is_root {
        io.print(&format!("\n{} {} [Y/n]: ", "[!]".red(), "This profile requires ROOT privileges. Attempt to elevate with sudo?".yellow().bold()));
        io.flush();
        let input = io.read_line();
        
        if input.trim().eq_ignore_ascii_case("y") || input.trim().is_empty() {
             use_sudo = true;
             let status = executor.execute("sudo", &["-", "v"]);
             if status.is_err() || !status.unwrap().success() {
                 io.println(&format!("{}", "[-] Sudo authentication failed. Aborting.".red()));
                 return;
             }
        } else {
             if custom_ports.is_none() {
                 io.println(&format!("{}", "    - Switching to Connect Scan (-sT) automatically.".yellow()));
                 profile = ScanProfile::new(
                    "Connect Scan (Fallback)",
                    "Non-root fallback. Uses full TCP handshake.",
                    &["-sT", "-sV", "--version-intensity", "5"],
                    false
                );
                // Re-init flags from fallback profile
                profile_flags = profile.flags.iter().map(|s| s.to_string()).collect();
                if skip_discovery { profile_flags.push("-Pn".to_string()); }
                if let Some(extras) = extra_args {
                    for arg in extras.split_whitespace() {
                        profile_flags.push(arg.to_string());
                    }
                }
             }
        }
    }
    
    io.println(&format!("{}", format!("\n[+] Selected Profile: {}", profile.name).green().bold()));
    io.println(&format!("    {}", profile.description));
    if let Some(e) = extra_args {
        io.println(&format!("    Extra Args: {}", e.cyan()));
    }

    let safe_target = target.replace('/', "_");
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/nmap/{}/{}", safe_target, date);

    if let Err(e) = fs::create_dir_all(&output_dir) {
        io.println(&format!("{} {}", "[!] Failed to create output directory:".red(), e));
        return;
    }

    io.println(&format!("{}", format!("[+] Starting Scan for {}", target).green()));
    io.println(&format!("[+] Results will be saved to {}", output_dir));

    // Step 1: Host Discovery
    io.println(&format!("\n{}", "[1] Running Host Discovery...".blue().bold()));
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}").unwrap());
    spinner.set_message("Discovering hosts...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    let host_file = format!("{}/host_discovery.txt", output_dir);
    
    let mut discovery_args = Vec::new();
    let mut has_discovery_override = false;

    if let Some(extras) = extra_args {
         if extras.contains("-sn") || extras.contains("-P") {
             has_discovery_override = true;
         }
    }
    
    if skip_discovery {
        discovery_args.push("-Pn");
    } else if !has_discovery_override {
        // Root users can use ICMP/ARP ping (-sn -PE etc). Non-root must rely on Connect/TCP ping.
        if is_root || use_sudo {
            discovery_args.push("-sn");
            if is_large_network {
                discovery_args.extend_from_slice(&[
                    "-n", "--max-retries", "1", "--min-rate", "1000", "-T4", 
                    "-PE", "-PS443", "-PA80"
                ]);
            } else {
                discovery_args.extend_from_slice(&["-PE", "-PP", "-PM"]);
            }
        } else {
            discovery_args.extend_from_slice(&["-sn", "-PS80,443,22,8080"]); 
        }
    }
    
    // Add extra args to discovery too, if they are relevant.
    if let Some(extras) = extra_args {
         for arg in extras.split_whitespace() {
             discovery_args.push(arg);
         }
    }

    discovery_args.push(target);
    discovery_args.push("-oN");
    discovery_args.push(&host_file);

    let mut final_cmd = "nmap";
    let mut final_args: Vec<String> = discovery_args.iter().map(|s| s.to_string()).collect();

    if use_proxy {
        final_args.insert(0, "nmap".to_string());
        final_cmd = "proxychains";
    }

    if use_sudo {
        final_args.insert(0, final_cmd.to_string());
        final_cmd = "sudo";
    }

    let final_args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();

    let output = executor.execute_output(final_cmd, &final_args_str);

    spinner.finish_and_clear();

    match output {
        Ok(out) => {
            if !out.status.success() {
                io.println(&format!("{}", "[!] Host discovery failed.".red()));
                let _ = append_history(&HistoryEntry::new("Nmap", target, "Failed"));
                return;
            }
        }
        Err(e) => {
            io.println(&format!("{} {}", "[!] Failed to execute nmap:".red(), e));
            let _ = append_history(&HistoryEntry::new("Nmap", target, "Failed"));
            return;
        }
    }

    // Parse Alive Hosts
    let content = fs::read_to_string(&host_file).unwrap_or_default();
    let re = Regex::new(r"Nmap scan report for ([\w\.-]+)").unwrap();
    let alive_hosts: Vec<String> = re.captures_iter(&content)
        .map(|cap| cap[1].to_string())
        .collect();

    if alive_hosts.is_empty() {
        io.println(&format!("{}", "[-] No alive hosts found.".yellow()));
        let _ = append_history(&HistoryEntry::new("Nmap", target, "No Hosts"));
        return;
    }

    io.println(&format!("{}", format!("[+] Found {} alive hosts.", alive_hosts.len()).green()));

    // Step 2: Deep Scan
    io.println(&format!("\n{}", "[2] Starting Deep Scans...".blue().bold()));
    
    let bar = ProgressBar::new(alive_hosts.len() as u64);
    bar.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
        .unwrap()
        .progress_chars("=>-"));
    bar.set_message("Scanning hosts...");
    bar.enable_steady_tick(std::time::Duration::from_secs(1));

    let hosts_queue = std::sync::Mutex::new(alive_hosts);
    let num_threads = if is_large_network { 10 } else { 4 };

    let scan_flags_str: Vec<&str> = profile_flags.iter().map(|s| s.as_str()).collect();

    std::thread::scope(|s| {
        for _ in 0..num_threads {
            s.spawn(|| {
                loop {
                    let host = {
                        let mut queue = hosts_queue.lock().unwrap();
                        queue.pop()
                    };

                    match host {
                        Some(h) => {
                            let scan_file = format!("{}/scan_{}", output_dir, h);
                            let (final_cmd, final_args) = build_nmap_command("nmap", &scan_flags_str, &h, &scan_file, use_proxy, use_sudo);
                            let final_args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();

                            let _ = executor.execute_silent(&final_cmd, &final_args_str);
                            bar.inc(1);
                        }
                        None => break,
                    }
                }
            });
        }
    });

    bar.finish_with_message("All scans complete!");
    io.println(&format!("{}", format!("\n[+] Scan completed. Results in {}", output_dir).green()));
    let _ = append_history(&HistoryEntry::new("Nmap", target, "Success"));
}

pub fn build_nmap_command(
    base_cmd: &str,
    flags: &[&str],
    target: &str,
    output_file: &str,
    use_proxy: bool,
    use_sudo: bool
) -> (String, Vec<String>) {
    let mut scan_args: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
    scan_args.push(target.to_string());
    if !output_file.is_empty() {
        scan_args.push("-oA".to_string());
        scan_args.push(output_file.to_string());
    }

    let mut final_cmd = base_cmd.to_string();
    let mut final_args = scan_args;

    if use_proxy {
        final_args.insert(0, final_cmd);
        final_cmd = "proxychains".to_string();
    }

    if use_sudo {
        final_args.insert(0, final_cmd);
        final_cmd = "sudo".to_string();
    }

    (final_cmd, final_args)
}

#[cfg(test)]
#[path = "nmap_tests.rs"]
mod tests;