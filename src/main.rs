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
pub mod dashboard;

use clap::{Parser, Subcommand};
use std::process::Command;
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

fn web_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    if let Some(config) = web::configure_web_enum(target, extra_args, &*executor, io) {
        let mut run_bg = false;
        if let Some(_) = &job_manager {
            io.print("\nRun scan in background? (y/N): ");
            io.flush();
            let input = io.read_line();
            if input.trim().eq_ignore_ascii_case("y") {
                run_bg = true;
            }
        }

        if run_bg {
            if let Some(jm) = job_manager {
                let config = config.clone();
                let executor = executor.clone();
                let proxy = use_proxy;
                let name = format!("WebEnum {}", config.target);
                
                jm.spawn_job(&name, move |ex, io| {
                    web::execute_web_enum(config, proxy, &*ex, io);
                }, executor, run_bg);
                io.println(&format!("{}", "Job started in background.".green()));
            }
        } else {
            web::execute_web_enum(config, use_proxy, &*executor, io);
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        }
    }
}

fn fuzzer_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    if let Some(config) = fuzzer::configure_fuzzer(target, None, extra_args, &*executor, io) {
        let mut run_bg = false;
        if let Some(_) = &job_manager {
            io.print("\nRun fuzzing in background? (y/N): ");
            io.flush();
            let input = io.read_line();
            if input.trim().eq_ignore_ascii_case("y") {
                run_bg = true;
            }
        }

        if run_bg {
            if let Some(jm) = job_manager {
                let config = config.clone();
                let executor = executor.clone();
                let proxy = use_proxy;
                let name = format!("Fuzzer {}", config.target);
                
                jm.spawn_job(&name, move |ex, io| {
                    fuzzer::execute_fuzzer(config, proxy, &*ex, io);
                }, executor, run_bg);
                io.println(&format!("{}", "Job started in background.".green()));
            }
        } else {
            fuzzer::execute_fuzzer(config, use_proxy, &*executor, io);
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        }
    }
}

fn exploit_search_wrapper(target: &str, _extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    if let Some(config) = search_exploit::configure_searchsploit(target, &*executor, io) {
        let mut run_bg = false;
        if let Some(_) = &job_manager {
            io.print("\nRun search in background? (y/N): ");
            io.flush();
            let input = io.read_line();
            if input.trim().eq_ignore_ascii_case("y") {
                run_bg = true;
            }
        }

        if run_bg {
            if let Some(jm) = job_manager {
                let config = config.clone();
                let executor = executor.clone();
                let proxy = use_proxy;
                let name = format!("SearchSploit {}", config.query);
                
                jm.spawn_job(&name, move |ex, io| {
                    search_exploit::execute_searchsploit(config, proxy, &*ex, io);
                }, executor, run_bg);
                io.println(&format!("{}", "Job started in background.".green()));
            }
        } else {
            search_exploit::execute_searchsploit(config, use_proxy, &*executor, io);
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        }
    }
}

fn exploit_active_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    if let Some(config) = exploit::configure_exploitation(target, None, extra_args, &*executor, io) {
        let mut run_bg = false;
        if let Some(_) = &job_manager {
            io.print("\nRun exploitation in background? (y/N): ");
            io.flush();
            let input = io.read_line();
            if input.trim().eq_ignore_ascii_case("y") {
                run_bg = true;
            }
        }

        if run_bg {
            if let Some(jm) = job_manager {
                let config = config.clone();
                let executor = executor.clone();
                let proxy = use_proxy;
                let name = "Exploitation Job"; 
                
                jm.spawn_job(name, move |ex, io| {
                    exploit::execute_exploitation(config, proxy, &*ex, io);
                }, executor, run_bg);
                io.println(&format!("{}", "Job started in background.".green()));
            }
        } else {
            exploit::execute_exploitation(config, use_proxy, &*executor, io);
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        }
    }
}

fn poison_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    if let Some(config) = poison::configure_poisoning(interface, &*executor, io) {
        let mut run_bg = false;
        if let Some(_) = &job_manager {
            io.print("\nRun poisoning in background? (y/N): ");
            io.flush();
            let input = io.read_line();
            if input.trim().eq_ignore_ascii_case("y") {
                run_bg = true;
            }
        }

        if run_bg {
            if let Some(jm) = job_manager {
                let config = config.clone();
                let executor = executor.clone();
                let proxy = use_proxy;
                let name = format!("Poisoning {}", config.interface);
                
                jm.spawn_job(&name, move |ex, io| {
                    poison::execute_poisoning(config, proxy, &*ex, io);
                }, executor, run_bg);
                io.println(&format!("{}", "Job started in background.".green()));
            }
        } else {
            poison::execute_poisoning(config, use_proxy, &*executor, io);
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        }
    }
}

fn wifi_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    if let Some(config) = wifi::configure_wifi(interface, &*executor, io) {
        let mut run_bg = false;
        if let Some(_) = &job_manager {
            io.print("\nRun WiFi audit in background? (y/N): ");
            io.flush();
            let input = io.read_line();
            if input.trim().eq_ignore_ascii_case("y") {
                run_bg = true;
            }
        }

        if run_bg {
            if let Some(jm) = job_manager {
                let config = config.clone();
                let executor = executor.clone();
                let proxy = use_proxy;
                let name = format!("WifiAudit {}", config.interface);
                
                jm.spawn_job(&name, move |ex, io| {
                    wifi::execute_wifi_audit(config, proxy, &*ex, io);
                }, executor, run_bg);
                io.println(&format!("{}", "Job started in background.".green()));
            }
        } else {
            wifi::execute_wifi_audit(config, use_proxy, &*executor, io);
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        }
    }
}

fn bluetooth_wrapper(arg: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    if let Some(config) = bluetooth::configure_bluetooth(arg, &*executor, io) {
        let mut run_bg = false;
        if let Some(_) = &job_manager {
            io.print("\nRun bluetooth attack in background? (y/N): ");
            io.flush();
            let input = io.read_line();
            if input.trim().eq_ignore_ascii_case("y") {
                run_bg = true;
            }
        }

        if run_bg {
            if let Some(jm) = job_manager {
                let config = config.clone();
                let executor = executor.clone();
                let proxy = use_proxy;
                let name = format!("Bluetooth {}", config.profile.name);
                
                jm.spawn_job(&name, move |ex, io| {
                    bluetooth::execute_bluetooth(config, proxy, &*ex, io);
                }, executor, run_bg);
                io.println(&format!("{}", "Job started in background.".green()));
            }
        } else {
            bluetooth::execute_bluetooth(config, use_proxy, &*executor, io);
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        }
    }
}

fn sniffer_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    if let Some(config) = sniffer::configure_sniffer(interface, &*executor, io) {
        let mut run_bg = false;
        if let Some(_) = &job_manager {
            io.print("\nRun sniffer in background? (y/N): ");
            io.flush();
            let input = io.read_line();
            if input.trim().eq_ignore_ascii_case("y") {
                run_bg = true;
            }
        }

        if run_bg {
            if let Some(jm) = job_manager {
                let config = config.clone();
                let executor = executor.clone();
                let proxy = use_proxy;
                let name = format!("Sniffer {}", config.interface);
                
                jm.spawn_job(&name, move |ex, io| {
                    sniffer::execute_sniffer(config, proxy, &*ex, io);
                }, executor, run_bg);
                io.println(&format!("{}", "Job started in background.".green()));
            }
        } else {
            sniffer::execute_sniffer(config, use_proxy, &*executor, io);
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
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
        io.println(&format!("[{}] Dashboard (Results & History)", main_menu.len() + 1));
        io.println(&format!("[{}] Toggle Proxychains", main_menu.len() + 2));
        io.println(&format!("[{}] Exit", main_menu.len() + 3));
        
        io.print(&format!("\n{}", "Select an option: ".green()));
        io.flush();

        let choice_str = io.read_line();
        if choice_str.is_empty() { break; } 
        
        if let Ok(choice_idx) = choice_str.trim().parse::<usize>() {
            if choice_idx > 0 && choice_idx <= main_menu.len() {
                // ... (Existing tool execution logic) ...
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
                dashboard::show_dashboard(&job_manager, io);
            } else if choice_idx == main_menu.len() + 2 {
                use_proxy = !use_proxy;
            } else if choice_idx == main_menu.len() + 3 {
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

// ... Wrappers ...


