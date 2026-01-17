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

use clap::{Parser, Subcommand};
use std::process::Command;

use colored::*;

use history::print_history;
use executor::{CommandExecutor, ShellExecutor};
use io_handler::{IoHandler, RealIoHandler};

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
    ///
    /// Executes an Nmap scan against the specified IP address or hostname. 
    /// Can be combined with --port, --no-ping, and --args.
    ///
    /// Example: --nmap 10.10.10.10
    #[arg(short, long)]
    pub nmap: Option<String>,

    /// Specify port(s) for Nmap
    ///
    /// Defines specific ports to scan. Supports single ports (80), ranges (80-100), 
    /// or lists (80,443,8080). Use "p-" for all ports.
    ///
    /// Example: --port "80,443"
    #[arg(long)]
    pub port: Option<String>,

    /// Skip Host Discovery (Nmap -Pn)
    ///
    /// Disables the initial ping scan (host discovery) and treats all hosts as online.
    /// Useful for firewalled targets that block ICMP.
    #[arg(long, default_value_t = false)]
    pub no_ping: bool,

    /// Pass extra arguments to the underlying tool
    ///
    /// Allows passing raw flags directly to the executed tool command (Nmap, Gobuster, etc.).
    /// Use quotes to pass multiple flags.
    ///
    /// Example: --args "-sC -sV --script=vuln"
    #[arg(long)]
    pub args: Option<String>,

    /// Specify sub-tool to use
    ///
    /// Selects a specific sub-tool for modules that support multiple engines.
    /// Currently used by the --exploit module (options: 'sqlmap', 'curl').
    ///
    /// Example: --tool sqlmap
    #[arg(long)]
    pub tool: Option<String>,

    /// Run WiFi Audit on interface
    ///
    /// Initiates a WiFi audit using Wifite on the specified wireless interface (e.g., wlan0).
    /// Requires root privileges.
    #[arg(long)]
    pub wifite: Option<String>,

    /// Run Packet Sniffer on interface
    ///
    /// Starts a packet capture (Tcpdump) on the specified interface.
    ///
    /// Example: --sniff eth0
    #[arg(short, long)]
    pub sniff: Option<String>,

    /// Run Web Enumeration on target URL
    ///
    /// Uses Gobuster to brute-force directories and files on the target web server.
    ///
    /// Example: --web http://example.com
    #[arg(long)]
    pub web: Option<String>,

    /// Run Web Fuzzing (ffuf) on target URL
    ///
    /// Fuzzes the target URL using Ffuf. The URL must contain the 'FUZZ' keyword
    /// to specify the injection point.
    ///
    /// Example: --fuzz http://example.com/FUZZ
    #[arg(long)]
    pub fuzz: Option<String>,

    /// Custom wordlist path
    ///
    /// Specifies a custom path to a wordlist file for Web Enumeration, Fuzzing, or Brute Force.
    ///
    /// Example: -w /usr/share/wordlists/rockyou.txt
    #[arg(short = 'w', long)]
    pub wordlist: Option<String>,

    /// Run Brute Force on target IP
    ///
    /// Initiates a brute-force attack (Hydra) against services on the target IP.
    /// Interactive mode will prompt for service type, user list, and password list.
    ///
    /// Example: --brute 192.168.1.50
    #[arg(long)]
    pub brute: Option<String>,

    /// Search for exploits (Searchsploit)
    ///
    /// Searches the Exploit-DB archive (via Searchsploit) for known vulnerabilities.
    /// Accepts a target IP (to parse Nmap XML results) or a direct Nmap XML file path.
    ///
    /// Example: --search-exploit 10.10.10.10
    #[arg(long)]
    pub search_exploit: Option<String>,

    /// Run Active Exploitation on target
    ///
    /// Launches the exploitation module. Supports automatic SQLMap execution or
    /// a sophisticated Curl request builder for manual exploitation.
    /// Use --tool to select the sub-tool.
    ///
    /// Example: --exploit http://vuln.com/id=1 --tool sqlmap
    #[arg(long)]
    pub exploit: Option<String>,

    /// Run LAN Poisoning on interface
    ///
    /// Starts network poisoning attacks (Responder) on the specified interface to
    /// capture credentials (LLMNR/NBT-NS poisoning).
    ///
    /// Example: --poison eth0
    #[arg(long)]
    pub poison: Option<String>,

    /// Run Bluetooth attacks
    ///
    /// Launches Bluetooth reconnaissance and attack tools (using bluetoothctl/hcitool).
    /// Accepts a target MAC address or "scan" to start discovery.
    ///
    /// Example: --bluetooth scan
    #[arg(long)]
    pub bluetooth: Option<String>,

    /// Enable Proxychains for evasion
    ///
    /// Wraps all executed commands with 'proxychains' to route traffic through
    /// configured proxies (e.g., Tor, SOCKS). Useful for evasion and anonymity.
    #[arg(short, long, default_value_t = false)]
    pub proxy: bool,
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum Commands {
    /// Show scan history
    ///
    /// Displays a log of previously executed scans, their targets, and status.
    History,
}

pub struct Tool {
    pub name: String,
    pub script: String,
    pub needs_arg: bool,
    pub arg_prompt: String,
    pub use_sudo: bool,
    pub function: Option<fn(&str, Option<&str>, bool, &dyn CommandExecutor, &dyn IoHandler)>,
}

impl Tool {
    pub fn new(name: &str, script: &str, needs_arg: bool, arg_prompt: &str, use_sudo: bool, func: Option<fn(&str, Option<&str>, bool, &dyn CommandExecutor, &dyn IoHandler)>) -> Self {
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

// Legacy script wrapper needs to ignore extra_args for now or we update it too.
// Since we are moving away from scripts, we'll just ignore it in legacy path.
pub fn run_legacy_script(script: &str, arg: &str, use_sudo: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    let _args = if !arg.is_empty() {
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
        Err(e) => io.println(&format!("{}", format!("[!] Failed to execute script: {}", e).red()))
    }

    io.print("\nPress Enter to return to menu...");
    io.flush();
    let _ = io.read_line();
}

// Wrappers to match the unified function signature: fn(&str, Option<&str>, bool, &dyn CommandExecutor, &dyn IoHandler)

fn nmap_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // In interactive mode, we don't support custom_ports/no_ping flags easily yet, 
    // unless we prompt for them. For now, we pass None/false but pass extra_args.
    nmap::run_nmap_scan(target, None, false, extra_args, use_proxy, executor, io); 
}

fn web_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    web::run_web_enum(target, extra_args, use_proxy, executor, io);
}

fn fuzzer_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    fuzzer::run_fuzzer(target, None, extra_args, use_proxy, executor, io);
}

fn exploit_search_wrapper(target: &str, _extra_args: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    search_exploit::run_searchsploit(target, use_proxy, executor, io);
}

fn exploit_active_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    // Wrapper for interactive mode: pass None for tool_name to trigger prompt
    exploit::run_exploitation_tool(target, None, extra_args, use_proxy, executor, io);
}

fn poison_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    poison::run_poisoning(interface, use_proxy, executor, io);
}
fn wifi_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    wifi::run_wifi_audit(interface, use_proxy, executor, io);
}
fn bluetooth_wrapper(arg: &str, _extra: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    bluetooth::run_bluetooth_attacks(arg, use_proxy, executor, io);
}
fn sniffer_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {
    sniffer::run_sniffer(interface, use_proxy, executor, io);
}

pub fn run_interactive_mode(mut use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {

    let main_menu = vec![

        Tool::new("Network Recon (Nmap & Discovery)", "", false, "", false, Some(recon_category)),

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

        io.println(&format!("[{}] Results Viewer", main_menu.len() + 1));

        io.println(&format!("[{}] View History", main_menu.len() + 2));

        io.println(&format!("[{}] Toggle Proxychains", main_menu.len() + 3));

        io.println(&format!("[{}] Exit", main_menu.len() + 4));

        

        io.print(&format!("\n{}", "Select an option: ".green()));

        io.flush();



        let choice_str = io.read_line();

        if choice_str.is_empty() { break; } 

        

        if let Ok(choice_idx) = choice_str.trim().parse::<usize>() {

            if choice_idx > 0 && choice_idx <= main_menu.len() {

                let tool = &main_menu[choice_idx - 1];

                let mut arg = String::new();

                

                                if tool.needs_arg {

                

                                    let last_target = history::get_last_target();

                

                                    let prompt = tool.arg_prompt.trim_end();

                

                                    arg = io.read_input(prompt, last_target.as_deref());

                

                                    

                

                                    if arg.is_empty() && !tool.arg_prompt.contains("Optional") && !tool.arg_prompt.contains("Leave empty") {

                

                                         continue;

                

                                    }

                

                                    if !arg.is_empty() && (prompt.contains("target") || prompt.contains("Target")) {

                

                                        history::save_last_target(&arg);

                

                                    }

                

                                }

                

                if let Some(func) = tool.function {

                    func(&arg, None, use_proxy, executor, io);

                    if tool.name.contains("Standalone") { // Only pause for standalone tools if needed

                        io.print("\nPress Enter to return to menu...");

                        io.flush();

                        let _ = io.read_line();

                    }

                }



            } else if choice_idx == main_menu.len() + 1 {

                report::view_results(io);

            } else if choice_idx == main_menu.len() + 2 {

                print_history(io);

                io.print("\nPress Enter to return...");

                io.flush();

                let _ = io.read_line();

            } else if choice_idx == main_menu.len() + 3 {

                use_proxy = !use_proxy;

            } else if choice_idx == main_menu.len() + 4 {

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



fn recon_category(_arg: &str, _extra: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {

    let tools = vec![

        Tool::new("Nmap Automator (Standard)", "nmap_automator.sh", true, "Enter target IP: ", true, Some(nmap_wrapper)),

        // We can add more specific Nmap profiles here as shortcuts if needed in future

    ];

    show_submenu("Network Recon", tools, use_proxy, executor, io);

}



fn web_category(_arg: &str, _extra: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {

    let tools = vec![

        Tool::new("Web Enumeration - Gobuster", "gobuster.sh", true, "Enter Target URL: ", false, Some(web_wrapper)),

        Tool::new("Web Fuzzing - Ffuf", "ffuf.sh", true, "Enter Target URL (with FUZZ): ", false, Some(fuzzer_wrapper)),

    ];

    show_submenu("Web Arsenal", tools, use_proxy, executor, io);

}



fn exploit_category(_arg: &str, _extra: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {

    let tools = vec![

        Tool::new("Exploit Search - Searchsploit", "search.sh", true, "Enter Search Query or Target IP/XML: ", false, Some(exploit_search_wrapper)),

        Tool::new("Active Exploitation (SQLMap, Curl, Hydra)", "exploit.sh", false, "", false, Some(exploit_active_wrapper)),

    ];

    show_submenu("Exploitation Hub", tools, use_proxy, executor, io);

}



fn netops_category(_arg: &str, _extra: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {

    let tools = vec![

        Tool::new("Packet Sniffer - Tcpdump", "packet_sniffer.sh", false, "", true, Some(sniffer_wrapper)),

        Tool::new("LAN Poisoning - Responder", "responder.sh", true, "Enter Interface: ", true, Some(poison_wrapper)),

    ];

    show_submenu("Network Operations", tools, use_proxy, executor, io);

}



fn wireless_category(_arg: &str, _extra: Option<&str>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {

    let tools = vec![

        Tool::new("WiFi Audit - Wifite", "wifi_audit.sh", true, "Enter Interface: ", true, Some(wifi_wrapper)),

        Tool::new("Bluetooth Arsenal", "bluetooth.sh", true, "Enter Target MAC (Optional): ", false, Some(bluetooth_wrapper)),

    ];

    show_submenu("Wireless & RF", tools, use_proxy, executor, io);

}



fn show_submenu(title: &str, tools: Vec<Tool>, use_proxy: bool, executor: &dyn CommandExecutor, io: &dyn IoHandler) {

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



                            let last_target = history::get_last_target();



                            let prompt = tool.arg_prompt.trim_end();



                            arg = io.read_input(prompt, last_target.as_deref());



                            



                            if arg.is_empty() && !tool.arg_prompt.contains("Optional") && !tool.arg_prompt.contains("Leave empty") {



                                 continue;



                            }



                            if !arg.is_empty() && (prompt.contains("target") || prompt.contains("Target")) {



                                history::save_last_target(&arg);



                            }



                        }



            if let Some(func) = tool.function {

                func(&arg, None, use_proxy, executor, io);

                io.print("\nPress Enter to return to menu...");

                io.flush();

                let _ = io.read_line();

            }

        }

        }

    }

    

    fn main() {
    // Global signal handler to prevent exit on Ctrl+C
    // This allows child processes (like tcpdump) to handle the signal and exit,
    // while the parent (purpl) stays alive and returns to menu.
    let _ = ctrlc::set_handler(move || {
        println!("\n{}", "^C Received".dimmed());
    });

    let cli = Cli::parse();
    let executor = ShellExecutor;
    let io = RealIoHandler;

    let use_proxy = cli.proxy;

    if let Some(target) = cli.nmap {
        nmap::run_nmap_scan(&target, cli.port.as_deref(), cli.no_ping, cli.args.as_deref(), use_proxy, &executor, &io);
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
        web::run_web_enum(&target, cli.args.as_deref(), use_proxy, &executor, &io);
        return;
    }

    if let Some(target) = cli.fuzz {
        fuzzer::run_fuzzer(&target, cli.wordlist.as_deref(), cli.args.as_deref(), use_proxy, &executor, &io);
        return;
    }

    if let Some(target) = cli.brute {
        brute::run_brute_force(&target, use_proxy, &executor, &io);
        return;
    }

    if let Some(target) = cli.search_exploit {
        search_exploit::run_searchsploit(&target, use_proxy, &executor, &io);
        return;
    }

    if let Some(target) = cli.exploit {
        exploit::run_exploitation_tool(&target, cli.tool.as_deref(), cli.args.as_deref(), use_proxy, &executor, &io);
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

    run_interactive_mode(use_proxy, &executor, &io);
}