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
pub mod ui;

use clap::{Parser, Subcommand};
use std::sync::Arc;

use colored::*;

use history::print_history;
use executor::{CommandExecutor, ShellExecutor};
use io_handler::{IoHandler, RealIoHandler};
use job_manager::JobManager;
use ui::clear_screen;

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
    let config = nmap::configure_nmap(target, None, false, extra_args, &*executor, io);
    
    let mut run_bg = false;
    if let Some(_) = &job_manager {
        io.print("\nRun task in background? (y/N): ");
        io.flush();
        let input = io.read_line();
        if input.trim().eq_ignore_ascii_case("y") {
            run_bg = true;
        }
    }

    run_tool_workflow(Some(config), use_proxy, executor, io, job_manager, 
        |cfg, p, ex, i| nmap::execute_nmap_scan(cfg, p, &*ex, i),
        |cfg| format!("Nmap {}", cfg.target),
        run_bg // Pass the decision
    );
}

fn web_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let config = web::configure_web_enum(target, extra_args, &*executor, io);
    
    let mut run_bg = false;
    if let Some(_) = &job_manager {
        io.print("\nRun task in background? (y/N): ");
        io.flush();
        let input = io.read_line();
        if input.trim().eq_ignore_ascii_case("y") {
            run_bg = true;
        }
    }

    run_tool_workflow(config, use_proxy, executor, io, job_manager, 
        |cfg, p, ex, i| web::execute_web_enum(cfg, p, &*ex, i),
        |cfg| format!("WebEnum {}", cfg.target),
        run_bg
    );
}

fn fuzzer_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let config = fuzzer::configure_fuzzer(target, None, extra_args, &*executor, io);
    
    let mut run_bg = false;
    if let Some(_) = &job_manager {
        io.print("\nRun task in background? (y/N): ");
        io.flush();
        let input = io.read_line();
        if input.trim().eq_ignore_ascii_case("y") {
            run_bg = true;
        }
    }

    run_tool_workflow(config, use_proxy, executor, io, job_manager, 
        |cfg, p, ex, i| fuzzer::execute_fuzzer(cfg, p, &*ex, i),
        |cfg| format!("Fuzzer {}", cfg.target),
        run_bg
    );
}

fn exploit_search_wrapper(target: &str, _extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let config = search_exploit::configure_searchsploit(target, &*executor, io);
    
    let mut run_bg = false;
    if let Some(_) = &job_manager {
        io.print("\nRun task in background? (y/N): ");
        io.flush();
        let input = io.read_line();
        if input.trim().eq_ignore_ascii_case("y") {
            run_bg = true;
        }
    }

    run_tool_workflow(config, use_proxy, executor, io, job_manager, 
        |cfg, p, ex, i| search_exploit::execute_searchsploit(cfg, p, &*ex, i),
        |cfg| format!("SearchSploit {}", cfg.query),
        run_bg
    );
}

fn exploit_active_wrapper(target: &str, extra_args: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let config = exploit::configure_exploitation(target, None, extra_args, &*executor, io);
    
    let mut run_bg = false;
    if let Some(_) = &job_manager {
        io.print("\nRun task in background? (y/N): ");
        io.flush();
        let input = io.read_line();
        if input.trim().eq_ignore_ascii_case("y") {
            run_bg = true;
        }
    }

    run_tool_workflow(config, use_proxy, executor, io, job_manager, 
        |cfg, p, ex, i| exploit::execute_exploitation(cfg, p, &*ex, i),
        |_cfg| "Exploitation Job".to_string(),
        run_bg
    );
}

fn poison_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let config = poison::configure_poisoning(interface, &*executor, io);
    
    let mut run_bg = false;
    if let Some(_) = &job_manager {
        io.print("\nRun task in background? (y/N): ");
        io.flush();
        let input = io.read_line();
        if input.trim().eq_ignore_ascii_case("y") {
            run_bg = true;
        }
    }

    run_tool_workflow(config, use_proxy, executor, io, job_manager, 
        |cfg, p, ex, i| poison::execute_poisoning(cfg, p, &*ex, i),
        |cfg| format!("Poisoning {}", cfg.interface),
        run_bg
    );
}

fn wifi_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let config = wifi::configure_wifi(interface, &*executor, io);
    
    let mut run_bg = false;
    if let Some(_) = &job_manager {
        io.print("\nRun task in background? (y/N): ");
        io.flush();
        let input = io.read_line();
        if input.trim().eq_ignore_ascii_case("y") {
            run_bg = true;
        }
    }

    run_tool_workflow(config, use_proxy, executor, io, job_manager, 
        |cfg, p, ex, i| wifi::execute_wifi_audit(cfg, p, &*ex, i),
        |cfg| format!("WifiAudit {}", cfg.interface),
        run_bg
    );
}

fn bluetooth_wrapper(arg: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let config = bluetooth::configure_bluetooth(arg, &*executor, io);
    
    let mut run_bg = false;
    if let Some(_) = &job_manager {
        io.print("\nRun task in background? (y/N): ");
        io.flush();
        let input = io.read_line();
        if input.trim().eq_ignore_ascii_case("y") {
            run_bg = true;
        }
    }

    run_tool_workflow(config, use_proxy, executor, io, job_manager, 
        |cfg, p, ex, i| bluetooth::execute_bluetooth(cfg, p, &*ex, i),
        |cfg| format!("Bluetooth {}", cfg.profile.name),
        run_bg
    );
}

fn sniffer_wrapper(interface: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let config = sniffer::configure_sniffer(interface, &*executor, io);
    
    let mut run_bg = false;
    if let Some(_) = &job_manager {
        io.print("\nRun task in background? (y/N): ");
        io.flush();
        let input = io.read_line();
        if input.trim().eq_ignore_ascii_case("y") {
            run_bg = true;
        }
    }

    run_tool_workflow(config, use_proxy, executor, io, job_manager, 
        |cfg, p, ex, i| sniffer::execute_sniffer(cfg, p, &*ex, i),
        |cfg| format!("Sniffer {}", cfg.interface),
        run_bg
    );
}


fn execute_tool(tool: &Tool, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {
    let mut arg = String::new();
    if tool.needs_arg {
        arg = ui::get_input_styled(io, &tool.arg_prompt);
        if arg.is_empty() && !tool.arg_prompt.contains("Optional") && !tool.arg_prompt.contains("Leave empty") {
             return;
        }
    }
    
    if let Some(func) = tool.function {
        func(&arg, None, use_proxy, executor, io, job_manager);
    }
}

pub fn run_interactive_mode(mut use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Arc<JobManager>) {
    let main_menu = vec![
        Tool::new("Network Recon (Nmap & Discovery)", "", false, "", false, Some(recon_category)),
        Tool::new("Web Arsenal (Gobuster, Ffuf)", "", false, "", false, Some(web_category)),
        Tool::new("Exploitation Hub (Search, Active, Hydra)", "", false, "", false, Some(exploit_category)),
        Tool::new("Network Operations (Sniffer, Poison)", "", false, "", false, Some(netops_category)),
        Tool::new("Wireless & RF (WiFi, Bluetooth)", "", false, "", false, Some(wireless_category)),
    ];

    loop {
        let menu_items: Vec<ui::MenuItem<&Tool>> = main_menu.iter()
            .map(|t| ui::MenuItem::new(&t.name, t))
            .collect();

        let proxy_status = if use_proxy { "ON".green() } else { "OFF".red() };
        let proxy_label = format!("Toggle Proxychains [{}]", proxy_status);
        
        let extras = vec![
            ("Dashboard (Results & History)", "D"),
            (proxy_label.as_str(), "P"),
            ("Exit", "0"),
        ];

        match ui::show_menu_loop(io, "Main Menu", &menu_items, &extras, true) {
            ui::MenuResult::Item(idx) => {
                let tool = &main_menu[idx];
                execute_tool(tool, use_proxy, executor.clone(), io, Some(job_manager.clone()));
            },
            ui::MenuResult::Extra(key) => {
                match key.as_str() {
                    "D" => dashboard::show_dashboard(&job_manager, io),
                    "P" => use_proxy = !use_proxy,
                    "0" => {
                        io.println("\nExiting. Stay safe!");
                        break;
                    },
                    _ => {}
                }
            },
            ui::MenuResult::Back => {
                // EOF or empty input on main menu
            }
        }
    }
}

// --- Category Wrappers ---



fn run_tool_workflow<C, F, N>(
    config: Option<C>,
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    task: F,
    name_gen: N,
    run_bg: bool,
) where
    C: Send + Sync + 'static + Clone,
    F: Fn(C, bool, &dyn CommandExecutor, &dyn IoHandler) + Send + Sync + 'static,
    N: Fn(&C) -> String + Send + Sync + 'static,
{
    if let Some(cfg) = config {
        if run_bg {
            if let Some(jm) = job_manager {
                let name = name_gen(&cfg);
                let task_arc = Arc::new(task);
                let task_clone = task_arc.clone();
                let cfg_arc = Arc::new(cfg);
                
                jm.spawn_job(&name, move |ex, i| {
                     let c = cfg_arc.clone();
                     task_clone((*c).clone(), use_proxy, &*ex, i);
                }, executor, true);
                
                io.println(&format!("{}", format!("Job '{}' started in background.", name).green()));
            } else {
                 io.println(&format!("{}", "[!] Job Manager not available.".red()));
                 // Fallback to foreground if user wanted BG but no manager?
                 task(cfg, use_proxy, &*executor, io);
                 io.print("\nPress Enter to return to menu...");
                 io.flush();
                 let _ = io.read_line();
            }
        } else {
            // Foreground
            task(cfg, use_proxy, &*executor, io);
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        }
    }
}

// We need to make sure Config types are Clone. 
// If they are not, we will get an error.
// For now, let's assume they are or modify the run_tool_workflow to require Clone.

// Actually, a simpler run_tool_workflow might just take a closure that does everything, 
// instead of splitting config and task.
// But the current calls in main.rs split them. 
// `run_tool_workflow(Some(config), ... |cfg, ...| ...)`

// Let's stick to the signature implied by main.rs but added Clone bound.

fn recon_category(_arg: &str, _extra: Option<&str>, use_proxy: bool, executor: Arc<dyn CommandExecutor + Send + Sync>, io: &dyn IoHandler, job_manager: Option<Arc<JobManager>>) {

    let tools = vec![

        Tool::new("Nmap Automator (Standard)", "nmap_automator.sh", true, "Enter target IP: ", true, Some(nmap_wrapper)),

        // We can add more specific Nmap profiles here as shortcuts if needed in future

    ];

    show_submenu("Network Recon", tools, use_proxy, executor, io, job_manager);

}



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

        ui::print_header(io, "PURPL CLI", Some(title));

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
                func(&arg, None, use_proxy, executor.clone(), io, job_manager.clone());
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