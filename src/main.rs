mod history;
mod nmap;
mod wifi;
mod report;
mod sniffer;
mod web;
mod brute;
mod exploit;
mod search_exploit;
mod poison;
mod bluetooth;
mod fuzzer;
pub mod executor;
pub mod io_handler;
pub mod job_manager;

use clap::{Parser, Subcommand};
use std::process::Command;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::thread;

use colored::*;

use history::print_history;
use executor::{CommandExecutor, ShellExecutor};
use io_handler::{IoHandler, RealIoHandler};
use job_manager::JobManager;

#[derive(Parser, Debug)]
#[command(name = "purpl")]
#[command(author = "CyberSecurity Team")]
#[command(version = "2.2.0")]
#[command(
    about = "Network Testing & Automation Tool (formerly lab_tool)",
    long_about = "PURPL is a comprehensive Command Line Interface (CLI) tool designed for network security assessments, penetration testing, and automation.
    
It integrates various industry-standard security tools (Nmap, Gobuster, Ffuf, Hydra, Searchsploit, etc.) into a unified workflow, offering both an interactive menu system and direct command-line execution for automation pipelines.

FEATURES:
- Network Scanning (Nmap): Custom profiles, host discovery, and deep scans.
- Web Enumeration (Gobuster): Directory and file brute-forcing with custom wordlists.
- Web Fuzzing (Ffuf): Parameter and endpoint fuzzing.
- Exploitation: Search for exploits (Searchsploit) and execute active attacks (SQLMap, Curl).
- Wireless Auditing: WiFi and Bluetooth attack vectors.
- Network Sniffing & Poisoning: Traffic analysis and man-in-the-middle attacks.
- Reporting & History: Automatic logging of scan results and command history.

USAGE EXAMPLES:
  purpl --nmap 192.168.1.1 --args \"-sV -sC\"
  purpl --web http://example.com --wordlist wordlists/common.txt
  purpl --exploit http://site.com/vuln.php --tool sqlmap
  purpl --fuzz http://site.com/FUZZ --args \"-mc 200\"
    "
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Run Nmap scan on target
    #[arg(short, long)]
    pub nmap: Option<String>,

    /// Specify port(s) for Nmap
    #[arg(long)]
    pub port: Option<String>,

    /// Skip Host Discovery (Nmap -Pn)
    #[arg(long, default_value_t = false)]
    pub no_ping: bool,

    /// Pass extra arguments to the underlying tool
    #[arg(long)]
    pub args: Option<String>,

    /// Specify sub-tool to use
    #[arg(long)]
    pub tool: Option<String>,

    /// Run WiFi Audit on interface
    #[arg(long)]
    pub wifite: Option<String>,

    /// Run Packet Sniffer on interface
    #[arg(short, long)]
    pub sniff: Option<String>,

    /// Run Web Enumeration on target URL
    #[arg(long)]
    pub web: Option<String>,

    /// Run Web Fuzzing (ffuf) on target URL
    #[arg(long)]
    pub fuzz: Option<String>,

    /// Custom wordlist path
    #[arg(short = 'w', long)]
    pub wordlist: Option<String>,

    /// Run Brute Force on target IP
    #[arg(long)]
    pub brute: Option<String>,

    /// Search for exploits (Searchsploit)
    #[arg(long)]
    pub search_exploit: Option<String>,

    /// Run Active Exploitation on target
    #[arg(long)]
    pub exploit: Option<String>,

    /// Run LAN Poisoning on interface
    #[arg(long)]
    pub poison: Option<String>,

    /// Run Bluetooth attacks
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
    pub script: String,
    pub needs_arg: bool,
    pub arg_prompt: String,
    pub use_sudo: bool,
    pub function: Option<fn(&str, Option<&str>, bool, Arc<dyn CommandExecutor + Send + Sync>, &dyn IoHandler, Option<Arc<JobManager>>)>, 
}

impl Tool {
    pub fn new(name: &str, script: &str, needs_arg: bool, arg_prompt: &str, use_sudo: bool, func: Option<fn(&str, Option<&str>, bool, Arc<dyn CommandExecutor + Send + Sync>, &dyn IoHandler, Option<Arc<JobManager>>)>) -> Self {
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
    io.println(&format!("{}", "    ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ".magenta().bold()));
    io.println(&format!("{}", "    ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ".bright_black().bold()));
    io.println(&format!("{}", "    ██████╔╝██║   ██║██████╔╝██████╔╝██║     ".magenta().bold()));
    io.println(&format!("{}", "    ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ".bright_black().bold()));
    io.println(&format!("{}", "    ██║     ╚██████╔╝██║  ██║██║     ███████╗".magenta().bold()));
    io.println(&format!("{}", "    ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝".bright_black().bold()));
    io.println(&format!("\n{}", "              PURPL Control Center | Rust Edition v2.2\n".magenta().bold()));
}

pub fn run_legacy_script(script: &str, arg: &str, use_sudo: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    let script_path = format!("./{}", script);
    let res = if use_sudo {
        let mut sudo_args = vec![script_path.as_str()];
        if !arg.is_empty() { sudo_args.push(arg); }
        executor.execute("sudo", &sudo_args)
    } else {
        let mut script_args = vec![];
        if !arg.is_empty() { script_args.push(arg); }
        executor.execute(&script_path, &script_args)
    };

    match res {
        Ok(_) => {{}},
        Err(e) => io.println(&format!("{}", format!("[!] Failed to execute script: {}", e).red()))
    }

    io.print("\nPress Enter to return to menu...");
    io.flush();
    let _ = io.read_line();
}

fn nmap_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    // 1. Configure
    let config = nmap::configure_nmap(target, None, false, extra_args, &*executor, io);
    
    // 2. Ask for Background (if job_manager available)
    let mut run_bg = false;
    if let Some(_) = &job_manager {
        io.print("\nRun scan in background? (y/N): ");
        io.flush();
        let input = io.read_line();
        if input.trim().eq_ignore_ascii_case("y") {
            run_bg = true;
        }
    }

    // 3. Create Job
    if let Some(jm) = job_manager {
        let config = config.clone();
        let executor_clone = executor.clone();
        let proxy = use_proxy;
        let name = format!("Nmap {}", config.target);
        
        let job = jm.spawn_job(&name, move |ex, io| {
            nmap::execute_nmap_scan(config, proxy, &*ex, io);
        }, executor_clone, run_bg);

        if !run_bg {
            // Foreground: Wait for job
            // Note: Since passthrough=true, output is already streaming to console via CapturingIoHandler
            while job.is_running() {
                thread::sleep(Duration::from_millis(100));
            }
            io.println("\nScan complete.");
            io.print("Press Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        } else {
            io.println(&format!("{}", "Job started in background.".green()));
            thread::sleep(Duration::from_secs(1));
        }
    } else {
        // Fallback (e.g. CLI non-interactive mode without job manager)
        nmap::execute_nmap_scan(config, use_proxy, &*executor, io);
    }
}

fn web_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, _jm: Option<Arc<JobManager>>) {
    web::run_web_enum(target, extra_args, use_proxy, &*executor, io);
}

fn fuzzer_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, _jm: Option<Arc<JobManager>>) {
    fuzzer::run_fuzzer(target, None, extra_args, use_proxy, &*executor, io);
}

fn exploit_search_wrapper(target: &str, _extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, _jm: Option<Arc<JobManager>>) {
    search_exploit::run_searchsploit(target, use_proxy, &*executor, io);
}

fn exploit_active_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, _jm: Option<Arc<JobManager>>) {
    exploit::run_exploitation_tool(target, None, extra_args, use_proxy, &*executor, io);
}

fn poison_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, _jm: Option<Arc<JobManager>>) {
    poison::run_poisoning(interface, use_proxy, &*executor, io);
}

fn wifi_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, _jm: Option<Arc<JobManager>>) {
    wifi::run_wifi_audit(interface, use_proxy, &*executor, io);
}

fn bluetooth_wrapper(arg: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, _jm: Option<Arc<JobManager>>) {
    bluetooth::run_bluetooth_attacks(arg, use_proxy, &*executor, io);
}

fn sniffer_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, _jm: Option<Arc<JobManager>>) {
    sniffer::run_sniffer(interface, use_proxy, &*executor, io);
}

fn view_background_jobs(job_manager: &JobManager, io: &dyn IoHandler) {
    loop {
        io.println(&format!("\n-- {} --", "Background Jobs".cyan().bold()));
        let jobs = job_manager.list_jobs();
        
        if jobs.is_empty() {
            io.println("No background jobs.");
            io.print("\nPress Enter to return...");
            io.flush();
            let _ = io.read_line();
            return;
        }

        io.println(&format!("{:<5} | {:<10} | {:<20} | {:<20}", "ID", "Status", "Start Time", "Name"));
        io.println(&"-".repeat(70));
        
        for job in &jobs {
            let status = job.status.lock().unwrap();
            let status_str = match *status {
                crate::job_manager::JobStatus::Running => "Running".yellow(),
                crate::job_manager::JobStatus::Completed => "Completed".green(),
                crate::job_manager::JobStatus::Failed => "Failed".red(),
            };
            io.println(&format!("{:<5} | {:<10} | {:<20} | {:<20}", 
                job.id, status_str, job.start_time, job.name.chars().take(20).collect::<String>()));
        }
        
        io.println("\n[ID] to view logs, [R]efresh, [0] Back");
        io.print("Select: ");
        io.flush();
        let input = io.read_line();
        let input_trim = input.trim();
        
        if input_trim == "0" { break; }
        if input_trim.eq_ignore_ascii_case("r") || input_trim.is_empty() { continue; }
        
        if let Ok(id) = input_trim.parse::<usize>() {
            if let Some(job) = job_manager.get_job(id) {
                io.println(&format!("\n-- Output for Job #{} ({}) --", job.id, job.name));
                io.println(&job.io.get_output());
                io.println("\n-- End of Output --");
                io.print("Press Enter to continue...");
                io.flush();
                let _ = io.read_line();
            } else {
                io.println(&format!("{}", "[!] Invalid Job ID.".red()));
            }
        }
    }
}

pub fn run_interactive_mode(mut use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Arc<JobManager>) {
    let main_menu = vec![
        Tool::new("Network Recon (Nmap)", "nmap_automator.sh", true, "Enter target IP: ", true, Some(nmap_wrapper)),
        Tool::new("Web Arsenal (Gobuster, Ffuf)", "", false, "", false, Some(web_category)),
        Tool::new("Exploitation Hub (Search, Active, Hydra)", "", false, "", false, Some(exploit_category)),
        Tool::new("Network Operations (Sniffer, Poison)", "", false, "", false, Some(netops_category)),
        Tool::new("Wireless & RF (WiFi, Bluetooth)", "", false, "", false, Some(wireless_category)),
    ];

    loop {
        clear_screen();
        print_banner(io);
        let proxy_status = if use_proxy { "ON".magenta().bold() } else { "OFF".dimmed() };
        io.println(&format!("              Proxychains: [{}]\n", proxy_status));

        for (i, tool) in main_menu.iter().enumerate() {
            io.println(&format!("[{}] {}", i + 1, tool.name));
        }
        io.println(&format!("[{}] View Scan Results", main_menu.len() + 1));
        io.println(&format!("[{}] View History", main_menu.len() + 2));
        io.println(&format!("[{}] View Background Jobs", main_menu.len() + 3));
        io.println(&format!("[{}] Toggle Proxychains", main_menu.len() + 4));
        io.println(&format!("[{}] Exit", main_menu.len() + 5));
        
        io.print(&format!("\n{}", "Select an option: ".green()));
        io.flush();

        let choice_str = io.read_line();
        if choice_str.is_empty() { break; } 
        
        if let Ok(choice_idx) = choice_str.trim().parse::<usize>() {
            if choice_idx > 0 && choice_idx <= main_menu.len() {
                let tool = &main_menu[choice_idx - 1];
                let mut arg = String::new();
                
                if tool.needs_arg {
                    io.print(&format!("{}", tool.arg_prompt));
                    io.flush();
                    let input = io.read_line();
                    arg = input.trim().to_string();
                    if arg.is_empty() && !tool.arg_prompt.contains("Optional") && !tool.arg_prompt.contains("Leave empty") {
                         continue;
                    }
                }
                
                if let Some(func) = tool.function {
                    func(&arg, None, use_proxy, executor.clone(), io, Some(job_manager.clone()));
                }
            } else if choice_idx == main_menu.len() + 1 {
                view_scan_results(io);
            } else if choice_idx == main_menu.len() + 2 {
                print_history(io);
                io.print("\nPress Enter to return...");
                io.flush();
                let _ = io.read_line();
            } else if choice_idx == main_menu.len() + 3 {
                view_background_jobs(&job_manager, io);
            } else if choice_idx == main_menu.len() + 4 {
                use_proxy = !use_proxy;
            } else if choice_idx == main_menu.len() + 5 {
                io.println("\nExiting. Stay safe!");
                break;
            } else {
                io.println(&format!("{}", "[!] Invalid choice.".red()));
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

// --- Category Wrappers ---

fn web_category(_arg: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let tools = vec![
        Tool::new("Web Enumeration - Gobuster", "gobuster.sh", true, "Enter Target URL: ", false, Some(web_wrapper)),
        Tool::new("Web Fuzzing - Ffuf", "ffuf.sh", true, "Enter Target URL (with FUZZ): ", false, Some(fuzzer_wrapper)),
    ];
    show_submenu("Web Arsenal", tools, use_proxy, executor, io, job_manager);
}

fn exploit_category(_arg: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let tools = vec![
        Tool::new("Exploit Search - Searchsploit", "search.sh", true, "Enter Search Query or Target IP/XML: ", false, Some(exploit_search_wrapper)),
        Tool::new("Active Exploitation (SQLMap, Curl, Hydra)", "exploit.sh", false, "", false, Some(exploit_active_wrapper)),
    ];
    show_submenu("Exploitation Hub", tools, use_proxy, executor, io, job_manager);
}

fn netops_category(_arg: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let tools = vec![
        Tool::new("Packet Sniffer - Tcpdump", "packet_sniffer.sh", false, "", true, Some(sniffer_wrapper)),
        Tool::new("LAN Poisoning - Responder", "responder.sh", true, "Enter Interface: ", true, Some(poison_wrapper)),
    ];
    show_submenu("Network Operations", tools, use_proxy, executor, io, job_manager);
}

fn wireless_category(_arg: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let tools = vec![
        Tool::new("WiFi Audit - Wifite", "wifi_audit.sh", true, "Enter Interface: ", true, Some(wifi_wrapper)),
        Tool::new("Bluetooth Arsenal", "bluetooth.sh", true, "Enter Target MAC (Optional): ", false, Some(bluetooth_wrapper)),
    ];
    show_submenu("Wireless & RF", tools, use_proxy, executor, io, job_manager);
}

fn show_submenu(title: &str, tools: Vec<Tool>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    loop {
        clear_screen();
        io.println(&format!("\n--- {} ---", title.cyan().bold()));
        for (i, tool) in tools.iter().enumerate() {
            io.println(&format!("[{}] {}", i + 1, tool.name));
        }
        io.println("[0] Back to Main Menu");

        io.print(&format!("\n{}", "Select an option: ".green()));
        io.flush();

        let choice_str = io.read_line();
        let choice_idx = choice_str.trim().parse::<usize>().unwrap_or(99);

        if choice_idx == 0 { break; }

        if choice_idx > 0 && choice_idx <= tools.len() {
            let tool = &tools[choice_idx - 1];
            let mut arg = String::new();

            if tool.needs_arg {
                io.print(&format!("{}", tool.arg_prompt));
                io.flush();
                let input = io.read_line();
                arg = input.trim().to_string();
                if arg.is_empty() && !tool.arg_prompt.contains("Optional") && !tool.arg_prompt.contains("Leave empty") {
                     continue;
                }
            }

            if let Some(func) = tool.function {
                func(&arg, None, use_proxy, executor.clone(), io, job_manager.clone());
            }
        }
    }
}

fn view_scan_results(io: &dyn IoHandler) {
    if !Path::new("scans").exists() {
        io.println(&format!("{}", "[!] No scans found yet.".yellow()));
        return;
    }

    loop {
        let tools_dir = match std::fs::read_dir("scans") {
            Ok(d) => d,
            Err(_) => return,
        };
        let mut tool_folders: Vec<_> = tools_dir.flatten()
            .filter(|e| e.path().is_dir())
            .collect();
        tool_folders.sort_by_key(|t| t.file_name());

        if tool_folders.is_empty() {
             io.println(&format!("{}", "No scan data found.".yellow()));
             return;
        }

        io.println(&format!("\n{}", "--- Scan Results Viewer ---".cyan().bold()));
        io.println(&format!("{}", "Select Tool Category:".blue().bold()));
        io.println("0. Back to Main Menu");
        for (i, tool) in tool_folders.iter().enumerate() {
            io.println(&format!("[{}] {}", i + 1, tool.file_name().to_string_lossy()));
        }
        
        io.print("\nSelect tool: ");
        io.flush();
        let t_in = io.read_line();
        let t_idx = t_in.trim().parse::<usize>().unwrap_or(9999);

        if t_idx == 0 { break; }
        if t_idx > tool_folders.len() { continue; }

        let selected_tool = &tool_folders[t_idx - 1];
        let tool_path = selected_tool.path();

        loop {
            let mut next_level_items: Vec<_> = std::fs::read_dir(&tool_path).unwrap()
                .flatten()
                .filter(|e| e.path().is_dir())
                .collect();
            
            if next_level_items.is_empty() {
                 io.println(&format!("{}", "[!] No records found.".yellow()));
                 break;
            }

            let is_dates_only = next_level_items.iter().all(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.len() >= 8 && name.chars().take(8).all(|c| c.is_digit(10))
            });

            if is_dates_only {
                next_level_items.sort_by_key(|e| e.file_name());
                next_level_items.reverse();
            } else {
                 next_level_items.sort_by_key(|e| e.file_name());
            }

            io.println(&format!("\n{}", format!("-- {} > Records --", selected_tool.file_name().to_string_lossy()).cyan()));
            if is_dates_only {
                 io.println(&format!("{}", "Select Scan Date:".blue().bold()));
            } else {
                 io.println(&format!("{}", "Select Target:".blue().bold()));
            }
            io.println("0. Back");
            
            for (i, item) in next_level_items.iter().enumerate() {
                 let name = item.file_name().to_string_lossy().to_string();
                 io.println(&format!("[{}] {}", i + 1, name));
            }

            io.print("\nSelect: ");
            io.flush();
            let item_in = io.read_line();
            let item_idx = item_in.trim().parse::<usize>().unwrap_or(9999);

            if item_idx == 0 { break; }
            if item_idx > next_level_items.len() { continue; }
            
            let selected_item = &next_level_items[item_idx - 1];

            if is_dates_only {
                report::display_scan_report(&selected_item.path(), io);
                io.print("\nPress Enter to continue...");
                io.flush();
                let _ = io.read_line();
            } else {
                loop {
                    let mut dates: Vec<_> = std::fs::read_dir(selected_item.path()).unwrap()
                        .flatten()
                        .filter(|e| e.path().is_dir())
                        .collect();
                    
                    if dates.is_empty() { break; }

                    dates.sort_by_key(|d| d.file_name());
                    dates.reverse();

                    io.println(&format!("\n{}", format!("-- {} > {} > Scans --", selected_tool.file_name().to_string_lossy(), selected_item.file_name().to_string_lossy()).cyan()));
                    io.println("0. Back");

                    for (j, date) in dates.iter().enumerate() {
                        io.println(&format!("[{}] {}", j + 1, date.file_name().to_string_lossy()));
                    }

                    io.print("\nSelect scan date: ");
                    io.flush();
                    let d_in = io.read_line();
                    let d_idx = d_in.trim().parse::<usize>().unwrap_or(9999);

                    if d_idx == 0 { break; }
                    if d_idx > dates.len() { continue; }

                    report::display_scan_report(&dates[d_idx - 1].path(), io);
                    io.print("\nPress Enter to continue...");
                    io.flush();
                    let _ = io.read_line();
                }
            }
        }
    }
}

fn main() {
    let _ = ctrlc::set_handler(move || {
        println!("\n{}", "^C Received".dimmed());
    });

    let cli = Cli::parse();
    let executor = Arc::new(ShellExecutor);
    let io = RealIoHandler;
    let job_manager = Arc::new(JobManager::new());
    let use_proxy = cli.proxy;

    if let Some(target) = cli.nmap {
        nmap::run_nmap_scan(&target, cli.port.as_deref(), cli.no_ping, cli.args.as_deref(), use_proxy, &*executor, &io);
        return;
    }

    if let Some(interface) = cli.wifite {
        wifi::run_wifi_audit(&interface, use_proxy, &*executor, &io);
        return;
    }

    if let Some(interface) = cli.sniff {
        sniffer::run_sniffer(&interface, use_proxy, &*executor, &io);
        return;
    }

    if let Some(target) = cli.web {
        web::run_web_enum(&target, cli.args.as_deref(), use_proxy, &*executor, &io);
        return;
    }

    if let Some(target) = cli.fuzz {
        fuzzer::run_fuzzer(&target, cli.wordlist.as_deref(), cli.args.as_deref(), use_proxy, &*executor, &io);
        return;
    }

    if let Some(target) = cli.brute {
        brute::run_brute_force(&target, use_proxy, &*executor, &io);
        return;
    }

    if let Some(target) = cli.search_exploit {
        search_exploit::run_searchsploit(&target, use_proxy, &*executor, &io);
        return;
    }

    if let Some(target) = cli.exploit {
        exploit::run_exploitation_tool(&target, cli.tool.as_deref(), cli.args.as_deref(), use_proxy, &*executor, &io);
        return;
    }

    if let Some(interface) = cli.poison {
        poison::run_poisoning(&interface, use_proxy, &*executor, &io);
        return;
    }

    if let Some(arg) = cli.bluetooth {
        bluetooth::run_bluetooth_attacks(&arg, use_proxy, &*executor, &io);
        return;
    }

    if let Some(Commands::History) = cli.command {
        print_history(&io);
        return;
    }

    run_interactive_mode(use_proxy, executor, &io, job_manager);
}

#[cfg(test)]
#[path = "main_bg_tests.rs"]
mod bg_tests;
