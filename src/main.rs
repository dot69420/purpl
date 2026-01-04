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
pub mod executor;
pub mod io_handler;

use clap::{Parser, Subcommand};
use std::process::Command;
use std::path::Path;
use std::io::Write;
use colored::*;
use history::print_history;
use executor::{CommandExecutor, ShellExecutor};
use io_handler::{IoHandler, RealIoHandler};

#[derive(Parser, Debug)]
#[command(name = "nt_test")]
#[command(about = "Network Testing & Automation Tool (formerly lab_tool)", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Run Nmap scan on target
    #[arg(short, long)]
    pub nmap: Option<String>,

    /// Run WiFi Audit on interface
    #[arg(short, long)]
    pub wifite: Option<String>,

    /// Run Packet Sniffer on interface
    #[arg(short, long)]
    pub sniff: Option<String>,

    /// Run Web Enumeration on target URL
    #[arg(long)]
    pub web: Option<String>,

    /// Run Brute Force on target IP
    #[arg(long)]
    pub brute: Option<String>,

    /// Run Exploit Search on target (IP or XML path)
    #[arg(long)]
    pub exploit: Option<String>,

    /// Run LAN Poisoning on interface
    #[arg(long)]
    pub poison: Option<String>,

    /// Run Bluetooth attacks (optional target MAC)
    #[arg(long)]
    pub bluetooth: Option<String>,

    /// Enable Proxychains for evasion
    #[arg(short, long, default_value_t = false)]
    pub proxy: bool,
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum Commands {
    /// Show scan history
    History,
}

pub struct Tool {
    pub name: String,
    // We keep script path just for reference or legacy, 
    // but we will try to use internal Rust functions first.
    pub script: String,
    pub needs_arg: bool,
    pub arg_prompt: String,
    pub use_sudo: bool,
    pub function: Option<fn(&str, bool, &dyn CommandExecutor, &dyn IoHandler)>, // Pointer to internal function
}

impl Tool {
    pub fn new(name: &str, script: &str, needs_arg: bool, arg_prompt: &str, use_sudo: bool, func: Option<fn(&str, bool, &dyn CommandExecutor, &dyn IoHandler)>) -> Self {
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

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

fn clear_screen() {
    let _ = Command::new("clear").status();
}

pub fn print_banner(io: &dyn IoHandler) {
    io.println(&format!("{}", "    ███╗   ██╗████████╗    ████████╗███████╗███████╗████████╗".green().bold()));
    io.println(&format!("{}", "    ████╗  ██║╚══██╔══╝    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝".green().bold()));
    io.println(&format!("{}", "    ██╔██╗ ██║   ██║          ██║   █████╗  ███████╗   ██║   ".green().bold()));
    io.println(&format!("{}", "    ██║╚██╗██║   ██║          ██║   ██╔══╝  ╚════██║   ██║   ".green().bold()));
    io.println(&format!("{}", "    ██║ ╚████║   ██║          ██║   ███████╗███████║   ██║   ".green().bold()));
    io.println(&format!("{}", "    ╚═╝  ╚═══╝   ╚═╝          ╚═╝   ╚══════╝╚══════╝   ╚═╝   ".green().bold()));
    io.println(&format!("\n{}", "              NT_TEST Control Center | Rust Edition v2.0\n".blue()));
}

pub fn run_legacy_script(script: &str, arg: &str, use_sudo: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    let args = if !arg.is_empty() {
        vec![arg]
    } else {
        vec![]
    };

    let script_path = format!("./{}", script);

    let res = if use_sudo {
        let mut sudo_args = vec![script_path.as_str()];
        if !arg.is_empty() {
            sudo_args.push(arg);
        }
        executor.execute("sudo", &sudo_args)
    } else {
        let mut script_args = vec![];
        if !arg.is_empty() {
            script_args.push(arg);
        }
        executor.execute(&script_path, &script_args)
    };

    match res {
        Ok(_) => {{}},
        Err(e) => io.println(&format!("{}", format!("[!] Failed to execute script: {}", e).red())),
    }

    io.print("\nPress Enter to return to menu...");
    io.flush();
    let _ = io.read_line();
}

pub fn run_interactive_mode(mut use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
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
        print_banner(io);
        
        // Proxy Status Indicator
        let proxy_status = if use_proxy { "ON".magenta().bold() } else { "OFF".dimmed() };
        io.println(&format!("              Proxychains: [{}]\n", proxy_status));

        for (i, tool) in tools.iter().enumerate() {
            io.println(&format!("[{}] {}", i + 1, tool.name));
        }
        io.println(&format!("[{}] View Scan Results", tools.len() + 1));
        io.println(&format!("[{}] View History", tools.len() + 2));
        io.println(&format!("[{}] Toggle Proxychains", tools.len() + 3));
        io.println(&format!("[{}] Exit", tools.len() + 4));
        
        io.print(&format!("\n{}", "Select an option: ".green()));
        io.flush();

        let choice_str = io.read_line();
        if choice_str.is_empty() {
            break; // EOF
        }
        let choice_str = choice_str.trim();

        if let Ok(choice_idx) = choice_str.parse::<usize>() {
            if choice_idx > 0 && choice_idx <= tools.len() {
                let tool = &tools[choice_idx - 1];
                let mut arg = String::new();
                
                if tool.needs_arg {
                    io.print(&format!("{}", tool.arg_prompt));
                    io.flush();
                    arg = io.read_line();
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
                    func(&arg, use_proxy, executor, io);
                    io.print("\nPress Enter to return to menu...");
                    io.flush();
                    let _ = io.read_line();
                } else {
                    run_legacy_script(&tool.script, &arg, tool.use_sudo, executor, io);
                }

            } else if choice_idx == tools.len() + 1 {
                // View Scan Results
                if !Path::new("scans").exists() {
                    io.println(&format!("{}", "[!] No scans found yet.".yellow()));
                } else {
                    if let Ok(targets) = std::fs::read_dir("scans") {
                        let mut targets: Vec<_> = targets.flatten().collect();
                        targets.sort_by_key(|t| t.file_name());

                        if targets.is_empty() {
                            io.println(&format!("{}", "No scan targets found.".yellow()));
                        } else {
                            io.println(&format!("\n{}", "Available Targets:".blue().bold()));
                            for (i, target) in targets.iter().enumerate() {
                                io.println(&format!("[{}] {}", i + 1, target.file_name().to_string_lossy()));
                            }
                            
                            io.print("\nSelect target: ");
                            io.flush();
                            let t_in = io.read_line();
                            
                            if let Ok(t_idx) = t_in.trim().parse::<usize>() {
                                if t_idx > 0 && t_idx <= targets.len() {
                                    let selected_target = &targets[t_idx - 1];
                                    
                                    // Now list dates for this target
                                    if let Ok(dates) = std::fs::read_dir(selected_target.path()) {
                                        let mut dates: Vec<_> = dates.flatten().collect();
                                        dates.sort_by_key(|d| d.metadata().ok().map(|m| m.modified().ok()).flatten());
                                        dates.reverse(); // Newest first

                                        io.println(&format!("\n{}", format!("Scans for {}:", selected_target.file_name().to_string_lossy()).blue().bold()));
                                        for (j, date) in dates.iter().enumerate() {
                                            io.println(&format!("[{}] {}", j + 1, date.file_name().to_string_lossy()));
                                        }

                                        io.print("\nSelect scan date: ");
                                        io.flush();
                                        let d_in = io.read_line();

                                        if let Ok(d_idx) = d_in.trim().parse::<usize>() {
                                            if d_idx > 0 && d_idx <= dates.len() {
                                                let selected_date = &dates[d_idx - 1];
                                                report::display_scan_report(&selected_date.path(), io);
                                            } else {
                                                io.println(&format!("{}", "Invalid date selection.".red()));
                                            }
                                        }
                                    }
                                } else {
                                    io.println(&format!("{}", "Invalid target selection.".red()));
                                }
                            }
                        }
                    }
                }

                io.print("\nPress Enter to return...");
                io.flush();
                let _ = io.read_line();
            } else if choice_idx == tools.len() + 2 {
                print_history(io);
                io.print("\nPress Enter to return...");
                io.flush();
                let _ = io.read_line();
            } else if choice_idx == tools.len() + 3 {
                use_proxy = !use_proxy;
            } else if choice_idx == tools.len() + 4 {
                io.println("\nExiting. Stay safe!");
                break;
            } else {
                io.println(&format!("{}", "[!] Invalid choice.".red()));
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        } else {
            io.println(&format!("{}", "[!] Invalid input.".red()));
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let executor = ShellExecutor;
    let io = RealIoHandler;

    // Global Proxy State
    let use_proxy = cli.proxy;

    // Handle Flags/Subcommands
    if let Some(target) = cli.nmap {
        nmap::run_nmap_scan(&target, use_proxy, &executor, &io);
        return;
    }

    if let Some(interface) = cli.wifite {
        wifi::run_wifi_audit(&interface, use_proxy, &executor, &io);
        return;
    }

    if let Some(interface) = cli.sniff {
        sniffer::run_sniffer(&interface, use_proxy, &executor, &io);
        return;
    }

    if let Some(target) = cli.web {
        web::run_web_enum(&target, use_proxy, &executor, &io);
        return;
    }

    if let Some(target) = cli.brute {
        brute::run_brute_force(&target, use_proxy, &executor, &io);
        return;
    }

    if let Some(target) = cli.exploit {
        exploit::run_exploit_search(&target, use_proxy, &executor, &io);
        return;
    }

    if let Some(interface) = cli.poison {
        poison::run_poisoning(&interface, use_proxy, &executor, &io);
        return;
    }

    if let Some(arg) = cli.bluetooth {
        bluetooth::run_bluetooth_attacks(&arg, use_proxy, &executor, &io);
        return;
    }

    if let Some(Commands::History) = cli.command {
        print_history(&io);
        return;
    }

    // Interactive Mode (Default)
    run_interactive_mode(use_proxy, &executor, &io);
}
