use std::fs;
use std::process::{Command, Stdio};
use std::io::{self, Write};
use chrono::Local;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use colored::*;
use crate::history::{append_history, HistoryEntry};

#[derive(Debug)]
struct ScanProfile {
    name: String,
    description: String,
    flags: Vec<&'static str>,
    requires_root: bool,
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

fn select_scan_profile(is_large_network: bool) -> ScanProfile {
    if is_large_network {
         println!("\n{}", "[!] Large Network Detected (Class A /8)".yellow().bold());
         println!("Auto-selecting 'Mass Scan' profile to prevent timeout/hanging.");
         return ScanProfile::new(
             "Mass Scan",
             "Optimized for large networks (No DNS, aggressive timing, rate limited)",
             &["-sS", "-sV", "-O", "-T4", "--max-retries", "1", "--version-light", "-n", "--min-rate", "1000"],
             true
         );
    }

    println!("\n{}", "Select Scan Profile:".blue().bold());
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
        println!("[{}] {} - {}", i + 1, profile.name.green(), profile.description);
    }

    print!("\nChoose a profile [1-{}]: ", profiles.len());
    let _ = io::stdout().flush();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();

    if let Ok(idx) = input.trim().parse::<usize>() {
        if idx > 0 && idx <= profiles.len() {
            let p = &profiles[idx - 1];
            return ScanProfile::new(&p.name, &p.description, &p.flags, p.requires_root);
        }
    }

    println!("{}", "[!] Invalid selection. Defaulting to 'Stealth & Vuln'.".yellow());
    ScanProfile::new(
        "Stealth & Vuln",
        "Default. TCP SYN scan + Service/OS detection + Vulnerability scripts. (Balanced)",
        &["-sS", "-sV", "-O", "--script", "vuln", "-T3", "--version-intensity", "5"],
        true
    )
}

pub fn run_nmap_scan(target: &str, use_proxy: bool) {
    let is_root = unsafe { libc::geteuid() } == 0;

    if use_proxy {
        println!("{}", "[*] Proxychains Enabled. Traffic will be routed through configured proxies.".magenta().bold());
    }

    if target.ends_with("/8") {
        println!("{}", "[!] Warning: Class A scan detected.".yellow());
    }

    // Select Profile
    let is_large_network = target.ends_with("/8");
    let mut profile = select_scan_profile(is_large_network);
    let mut use_sudo = false;

    if profile.requires_root && !is_root {
        print!("\n{} {} [Y/n]: ", "[!]".red(), "This profile requires ROOT privileges. Attempt to elevate with sudo?".yellow().bold());
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap_or_default();
        
        if input.trim().eq_ignore_ascii_case("y") || input.trim().is_empty() {
             use_sudo = true;
             // Validate sudo credentials immediately so subsequent commands don't hang/fail hiddenly
             let status = Command::new("sudo")
                .arg("-v")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status();
            
             if status.is_err() || !status.unwrap().success() {
                 println!("{}", "[-] Sudo authentication failed. Aborting.".red());
                 return;
             }
        } else {
             println!("{}", "    - Switching to 'Connect Scan' (-sT) automatically.".yellow());
             profile = ScanProfile::new(
                "Connect Scan (Fallback)",
                "Non-root fallback. Uses full TCP handshake.",
                &["-sT", "-sV", "--version-intensity", "5"],
                false
            );
        }
    }
    
    println!("{}", format!("\n[+] Selected Profile: {}", profile.name).green().bold());
    println!("    {}", profile.description);

    let safe_target = target.replace('/', "_");
    let date = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("scans/{}/{}", safe_target, date);

    if let Err(e) = fs::create_dir_all(&output_dir) {
        println!("{} {}", "[!] Failed to create output directory:".red(), e);
        return;
    }

    println!("{}", format!("[+] Starting Scan for {}", target).green());
    println!("[+] Results will be saved to {}", output_dir);

    // Step 1: Host Discovery
    println!("\n{}", "[1] Running Host Discovery...".blue().bold());
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg}").unwrap());
    spinner.set_message("Discovering hosts...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    let host_file = format!("{}/host_discovery.txt", output_dir);
    
    let mut discovery_args = Vec::new();
    
    // Root users can use ICMP/ARP ping (-sn -PE etc). Non-root must rely on Connect/TCP ping.
    // If we are using sudo, we are effectively root.
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
        // Non-root discovery (TCP Connect Ping)
        discovery_args.extend_from_slice(&["-sn", "-PS80,443,22,8080"]); 
    }
    
    discovery_args.push(target);
    discovery_args.push("-oN");
    discovery_args.push(&host_file);

    // Command Construction: [sudo] [proxychains] nmap [args]
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

    // Convert Vec<String> to Vec<&str> for Command::args
    let final_args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();

    let output = Command::new(final_cmd)
        .args(&final_args_str)
        .output();

    spinner.finish_and_clear();

    match output {
        Ok(out) => {
            if !out.status.success() {
                println!("{}", "[!] Host discovery failed.".red());
                let _ = append_history(&HistoryEntry::new("Nmap", target, "Failed"));
                return;
            }
        }
        Err(e) => {
            println!("{} {}", "[!] Failed to execute nmap:".red(), e);
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
        println!("{}", "[-] No alive hosts found.".yellow());
        let _ = append_history(&HistoryEntry::new("Nmap", target, "No Hosts"));
        return;
    }

    println!("{}", format!("[+] Found {} alive hosts.", alive_hosts.len()).green());

    // Step 2: Deep Scan
    println!("\n{}", "[2] Starting Deep Scans...".blue().bold());
    
    let bar = ProgressBar::new(alive_hosts.len() as u64);
    bar.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
        .unwrap()
        .progress_chars("=>-"));

    for host in &alive_hosts {
        bar.set_message(format!("Scanning {}", host));
        
        let scan_file = format!("{}/scan_{}", output_dir, host);
        let mut scan_args = profile.flags.clone(); // Use the selected profile flags
        scan_args.push(host);
        scan_args.push("-oA");
        scan_args.push(&scan_file);

        // Command Construction: [sudo] [proxychains] nmap [args]
        let mut final_cmd = "nmap";
        let mut final_args: Vec<String> = scan_args.iter().map(|s| s.to_string()).collect();

        if use_proxy {
            final_args.insert(0, "nmap".to_string());
            final_cmd = "proxychains";
        }

        if use_sudo {
            final_args.insert(0, final_cmd.to_string());
            final_cmd = "sudo";
        }
        
        let final_args_str: Vec<&str> = final_args.iter().map(|s| s.as_str()).collect();

        let _ = Command::new(final_cmd)
            .args(&final_args_str)
            .stdout(Stdio::null()) // Suppress nmap output to keep progress bar clean
            .stderr(Stdio::null())
            .status();
        
        bar.inc(1);
    }

    bar.finish_with_message("All scans complete!");
    println!("{}", format!("\n[+] Scan completed. Results in {}", output_dir).green());
    let _ = append_history(&HistoryEntry::new("Nmap", target, "Success"));
}
