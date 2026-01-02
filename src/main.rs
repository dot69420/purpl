mod history;
mod nmap;
mod wifi;
mod report;
mod sniffer;
mod web;
mod brute;
mod exploit;
mod poison;
mod bluetooth;

use clap::{Parser, Subcommand};
use std::process::Command;
use std::path::Path;
use std::io::{self, Write};
use colored::*;
use history::print_history;

#[derive(Parser)]
#[command(name = "nt_test")]
#[command(about = "Network Testing & Automation Tool (formerly lab_tool)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run Nmap scan on target
    #[arg(short, long)]
    nmap: Option<String>,

    /// Run WiFi Audit on interface
    #[arg(short, long)]
    wifite: Option<String>,

    /// Run Packet Sniffer on interface
    #[arg(short, long)]
    sniff: Option<String>,

    /// Run Web Enumeration on target URL
    #[arg(long)]
    web: Option<String>,

    /// Run Brute Force on target IP
    #[arg(long)]
    brute: Option<String>,

    /// Run Exploit Search on target (IP or XML path)
    #[arg(long)]
    exploit: Option<String>,

    /// Run LAN Poisoning on interface
    #[arg(long)]
    poison: Option<String>,

    /// Run Bluetooth attacks (optional target MAC)
    #[arg(long)]
    bluetooth: Option<String>,

    /// Enable Proxychains for evasion
    #[arg(short, long, default_value_t = false)]
    proxy: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Show scan history
    History,
}

struct Tool {
    name: String,
    // We keep script path just for reference or legacy, 
    // but we will try to use internal Rust functions first.
    script: String, 
    needs_arg: bool,
    arg_prompt: String,
    use_sudo: bool,
    function: Option<fn(&str, bool)>, // Pointer to internal function
}

impl Tool {
    fn new(name: &str, script: &str, needs_arg: bool, arg_prompt: &str, use_sudo: bool, func: Option<fn(&str, bool)>) -> Self {
        Self {
            name: name.to_string(),
            script: script.to_string(),
            needs_arg,
            arg_prompt: arg_prompt.to_string(),
            use_sudo,
            function: func,
        }
    }
}

fn clear_screen() {
    let _ = Command::new("clear").status();
}

fn print_banner() {
    println!("{}", "    ███╗   ██╗████████╗    ████████╗███████╗███████╗████████╗".green().bold());
    println!("{}", "    ████╗  ██║╚══██╔══╝    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝".green().bold());
    println!("{}", "    ██╔██╗ ██║   ██║          ██║   █████╗  ███████╗   ██║   ".green().bold());
    println!("{}", "    ██║╚██╗██║   ██║          ██║   ██╔══╝  ╚════██║   ██║   ".green().bold());
    println!("{}", "    ██║ ╚████║   ██║          ██║   ███████╗███████║   ██║   ".green().bold());
    println!("{}", "    ╚═╝  ╚═══╝   ╚═╝          ╚═╝   ╚══════╝╚══════╝   ╚═╝   ".green().bold());
    println!("\n{}", "              NT_TEST Control Center | Rust Edition v2.0\n".blue());
}

fn run_legacy_script(script: &str, arg: &str, use_sudo: bool) {
    let mut cmd = if use_sudo {
        let mut c = Command::new("sudo");
        c.arg(format!("./{}", script));
        c
    } else {
        Command::new(format!("./{}", script))
    };

    if !arg.is_empty() {
        cmd.arg(arg);
    }

    cmd.stdin(std::process::Stdio::inherit())
       .stdout(std::process::Stdio::inherit())
       .stderr(std::process::Stdio::inherit());

    match cmd.status() {
        Ok(_) => {{}},
        Err(e) => println!("{}", format!("[!] Failed to execute script: {}", e).red()),
    }

    print!("\nPress Enter to return to menu...");
    let _ = io::stdout().flush();
    let mut temp = String::new();
    let _ = io::stdin().read_line(&mut temp);
}

fn main() {
    let cli = Cli::parse();

    // Global Proxy State
    let mut use_proxy = cli.proxy;

    // Handle Flags/Subcommands
    if let Some(target) = cli.nmap {
        nmap::run_nmap_scan(&target, use_proxy);
        return;
    }

    if let Some(interface) = cli.wifite {
        wifi::run_wifi_audit(&interface, use_proxy);
        return;
    }

    if let Some(interface) = cli.sniff {
        sniffer::run_sniffer(&interface, use_proxy);
        return;
    }

    if let Some(target) = cli.web {
        web::run_web_enum(&target, use_proxy);
        return;
    }

    if let Some(target) = cli.brute {
        brute::run_brute_force(&target, use_proxy);
        return;
    }

    if let Some(target) = cli.exploit {
        exploit::run_exploit_search(&target, use_proxy);
        return;
    }

    if let Some(interface) = cli.poison {
        poison::run_poisoning(&interface, use_proxy);
        return;
    }

    if let Some(arg) = cli.bluetooth {
        bluetooth::run_bluetooth_attacks(&arg, use_proxy);
        return;
    }

    if let Some(Commands::History) = cli.command {
        print_history();
        return;
    }

    // Interactive Mode (Default)
    let tools = vec![
        Tool::new("Network Scan (Nmap Automation)", "nmap_automator.sh", true, "Enter target IP or Range: ", true, Some(nmap::run_nmap_scan)),
        Tool::new("Web Enumeration (Gobuster)", "gobuster.sh", true, "Enter Target URL (http://...): ", false, Some(web::run_web_enum)),
        Tool::new("Exploit Search (Searchsploit)", "search.sh", true, "Enter Target IP (to find Nmap report): ", false, Some(exploit::run_exploit_search)),
        Tool::new("Credential Access (Hydra)", "hydra.sh", true, "Enter Target IP: ", false, Some(brute::run_brute_force)),
        Tool::new("LAN Poisoning (Responder)", "responder.sh", true, "Enter Interface (Leave empty to list): ", true, Some(poison::run_poisoning)),
        Tool::new("WiFi Audit (Wifite Automation)", "wifi_audit.sh", true, "Enter Wireless Interface: ", true, Some(wifi::run_wifi_audit)),
        Tool::new("Bluetooth Arsenal (BlueZ)", "bluetooth.sh", true, "Enter Target MAC (Optional, leave empty): ", false, Some(bluetooth::run_bluetooth_attacks)),
        Tool::new("Packet Sniffer (Traffic Analysis)", "packet_sniffer.sh", true, "Enter Interface to Sniff: ", true, Some(sniffer::run_sniffer)),
    ];

    loop {
        clear_screen();
        print_banner();
        
        // Proxy Status Indicator
        let proxy_status = if use_proxy { "ON".magenta().bold() } else { "OFF".dimmed() };
        println!("              Proxychains: [{}]\n", proxy_status);

        for (i, tool) in tools.iter().enumerate() {
            println!("[{}] {}", i + 1, tool.name);
        }
        println!("[{}] View Scan Results", tools.len() + 1);
        println!("[{}] View History", tools.len() + 2);
        println!("[{}] Toggle Proxychains", tools.len() + 3);
        println!("[{}] Exit", tools.len() + 4);
        
        print!("\n{}", "Select an option: ".green());
        let _ = io::stdout().flush();

        let mut choice_str = String::new();
        io::stdin().read_line(&mut choice_str).expect("Failed to read line");
        let choice_str = choice_str.trim();

        if let Ok(choice_idx) = choice_str.parse::<usize>() {
            if choice_idx > 0 && choice_idx <= tools.len() {
                let tool = &tools[choice_idx - 1];
                let mut arg = String::new();
                
                if tool.needs_arg {
                    print!("{}", tool.arg_prompt);
                    let _ = io::stdout().flush();
                    io::stdin().read_line(&mut arg).expect("Failed to read line");
                    arg = arg.trim().to_string();
                    if arg.is_empty() && tool.arg_prompt.contains("Optional") {
                         // Allowed empty
                    } else if arg.is_empty() && tool.arg_prompt.contains("Leave empty") {
                         // Allowed empty
                    } else if arg.is_empty() {
                         continue;
                    }
                }
                
                // Use Rust implementation if available, else legacy script
                if let Some(func) = tool.function {
                    func(&arg, use_proxy);
                    print!("\nPress Enter to return to menu...");
                    let _ = io::stdout().flush();
                    let mut temp = String::new();
                    let _ = io::stdin().read_line(&mut temp);
                } else {
                    run_legacy_script(&tool.script, &arg, tool.use_sudo);
                }

            } else if choice_idx == tools.len() + 1 {
                // View Scan Results
                if !Path::new("scans").exists() {
                    println!("{}", "[!] No scans found yet.".yellow());
                } else {
                    // Recursively or just top-level? 
                    // Structure is scans/<target>/<date>/...
                    // Let's list targets first, then dates.
                    
                    if let Ok(targets) = std::fs::read_dir("scans") {
                        let mut targets: Vec<_> = targets.flatten().collect();
                        targets.sort_by_key(|t| t.file_name());

                        if targets.is_empty() {
                            println!("{}", "No scan targets found.".yellow());
                        } else {
                            println!("\n{}", "Available Targets:".blue().bold());
                            for (i, target) in targets.iter().enumerate() {
                                println!("[{}] {}", i + 1, target.file_name().to_string_lossy());
                            }
                            
                            print!("\nSelect target: ");
                            let _ = io::stdout().flush();
                            let mut t_in = String::new();
                            io::stdin().read_line(&mut t_in).unwrap_or_default();
                            
                            if let Ok(t_idx) = t_in.trim().parse::<usize>() {
                                if t_idx > 0 && t_idx <= targets.len() {
                                    let selected_target = &targets[t_idx - 1];
                                    
                                    // Now list dates for this target
                                    if let Ok(dates) = std::fs::read_dir(selected_target.path()) {
                                        let mut dates: Vec<_> = dates.flatten().collect();
                                        dates.sort_by_key(|d| d.metadata().ok().map(|m| m.modified().ok()).flatten());
                                        dates.reverse(); // Newest first

                                        println!("\n{}", format!("Scans for {}:", selected_target.file_name().to_string_lossy()).blue().bold());
                                        for (j, date) in dates.iter().enumerate() {
                                            println!("[{}] {}", j + 1, date.file_name().to_string_lossy());
                                        }

                                        print!("\nSelect scan date: ");
                                        let _ = io::stdout().flush();
                                        let mut d_in = String::new();
                                        io::stdin().read_line(&mut d_in).unwrap_or_default();

                                        if let Ok(d_idx) = d_in.trim().parse::<usize>() {
                                            if d_idx > 0 && d_idx <= dates.len() {
                                                let selected_date = &dates[d_idx - 1];
                                                report::display_scan_report(&selected_date.path());
                                            } else {
                                                println!("{}", "Invalid date selection.".red());
                                            }
                                        }
                                    }
                                } else {
                                    println!("{}", "Invalid target selection.".red());
                                }
                            }
                        }
                    }
                }

                print!("\nPress Enter to return...");
                let _ = io::stdout().flush();
                let mut temp = String::new();
                let _ = io::stdin().read_line(&mut temp);
            } else if choice_idx == tools.len() + 2 {
                print_history();
                print!("\nPress Enter to return...");
                let _ = io::stdout().flush();
                let mut temp = String::new();
                let _ = io::stdin().read_line(&mut temp);
            } else if choice_idx == tools.len() + 3 {
                use_proxy = !use_proxy;
            } else if choice_idx == tools.len() + 4 {
                println!("\nExiting. Stay safe!");
                break;
            } else {
                println!("{}", "[!] Invalid choice.".red());
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        } else {
            println!("{}", "[!] Invalid input.".red());
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}
