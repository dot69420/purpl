mod api;
mod bluetooth;
mod brute;
pub mod dashboard;
pub mod executor;
mod exploit;
mod fuzzer;
mod history;
pub mod input_provider;
pub mod io_handler;
pub mod job_manager;
mod nmap;
mod poison;
mod report;
mod search_exploit;
mod sniffer;
pub mod tool_model;
pub mod ui;
mod validation;
mod web;
mod wifi;

use clap::{Parser, Subcommand};
use std::fs;
use std::sync::Arc;

use colored::*;

use executor::{CommandExecutor, HybridExecutor, ShellExecutor};
use history::print_history;
use input_provider::{CliInputProvider, InputProvider};
use io_handler::{IoHandler, RealIoHandler};
use job_manager::{Job, JobManager};
use tool_model::{
    MenuCategory, SpecializedStrategy, Tool, ToolImplementation, ToolInput, ToolSpecification,
};
use ui::clear_screen;

#[derive(Parser, Debug)]
#[command(name = "purpl")]
#[command(author = "CyberSecurity Team")]
#[command(version = "2.6.0")]
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
- Custom Tools: Extensible toolbox for user-defined commands.
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

    /// Run tools in a Docker container
    #[arg(long, default_value_t = false)]
    pub container: bool,

    /// Docker image to use (default: purpl-tools)
    #[arg(long, default_value = "purpl-tools")]
    pub image: String,
}

#[derive(Subcommand, Debug, PartialEq)]
pub enum Commands {
    /// Show scan history
    History,
    /// Start API Server
    Serve {
        #[arg(short, long, default_value_t = 3000)]
        port: u16,
        #[arg(long, default_value_t = false)]
        container: bool,
        #[arg(long, default_value = "purpl-tools")]
        image: String,
    },
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

pub fn run_interactive_mode(
    mut use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Arc<JobManager>,
) {
    let main_menu = vec![
        Tool::category("Network Recon (Nmap & Discovery)", MenuCategory::Recon),
        Tool::category("Web Arsenal (Gobuster, Ffuf)", MenuCategory::Web),
        Tool::category(
            "Exploitation Hub (Search, Active, Hydra)",
            MenuCategory::Exploit,
        ),
        Tool::category("Network Operations (Sniffer, Poison)", MenuCategory::NetOps),
        Tool::category("Wireless & RF (WiFi, Bluetooth)", MenuCategory::Wireless),
        Tool::category("Custom Toolbox (User Defined)", MenuCategory::UserTools),
    ];

    let input_provider = CliInputProvider::new(io);

    loop {
        let menu_items: Vec<ui::MenuItem<&Tool>> = main_menu
            .iter()
            .map(|t| ui::MenuItem::new(&t.name, t))
            .collect();

        let proxy_status = if use_proxy { "ON".green() } else { "OFF".red() };
        let proxy_label = format!(
            "Toggle Proxychains [{}]
",
            proxy_status
        );

        let extras = vec![
            ("Dashboard (Results & History)", "D"),
            (proxy_label.as_str(), "P"),
            ("Exit", "0"),
        ];

        match ui::show_menu_loop(io, "Main Menu", &menu_items, &extras, true) {
            ui::MenuResult::Item(idx) => {
                let tool = &main_menu[idx];
                run_tool_dispatch(
                    tool,
                    use_proxy,
                    executor.clone(),
                    io,
                    Some(job_manager.clone()),
                    &input_provider,
                );
            }
            ui::MenuResult::Extra(key) => match key.as_str() {
                "D" => dashboard::show_dashboard(&job_manager, io),
                "P" => use_proxy = !use_proxy,
                "0" => {
                    io.println("\nExiting. Stay safe!");
                    break;
                }
                _ => {}
            },
            ui::MenuResult::Back => {
                break;
            }
        }
    }
}

fn run_tool_dispatch(
    tool: &Tool,
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    input: &dyn InputProvider,
) {
    match &tool.implementation {
        ToolImplementation::Specialized(strategy) => {
            run_specialized_logic(*strategy, use_proxy, executor, io, job_manager, input)
        }
        ToolImplementation::Standard(spec) => run_standard_tool(
            spec,
            use_proxy,
            executor,
            io,
            job_manager,
            &tool.name,
            input,
        ),
        ToolImplementation::Submenu(category) => {
            run_category_logic(*category, use_proxy, executor, io, job_manager, input)
        }
        ToolImplementation::PlaceholderAdd => add_custom_tool_flow(io, input),
    }
}

fn run_category_logic(
    category: MenuCategory,
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    input: &dyn InputProvider,
) {
    match category {
        MenuCategory::Recon => recon_category(use_proxy, executor, io, job_manager, input),
        MenuCategory::Web => web_category(use_proxy, executor, io, job_manager, input),
        MenuCategory::Exploit => exploit_category(use_proxy, executor, io, job_manager, input),
        MenuCategory::NetOps => netops_category(use_proxy, executor, io, job_manager, input),
        MenuCategory::Wireless => wireless_category(use_proxy, executor, io, job_manager, input),
        MenuCategory::UserTools => {
            custom_tools_category(use_proxy, executor, io, job_manager, input)
        }
    }
}

fn run_specialized_logic(
    strategy: SpecializedStrategy,
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    input: &dyn InputProvider,
) {
    match strategy {
        SpecializedStrategy::Nmap => {
            // Nmap is complex, partially legacy. We use input provider for initial args.
            // TODO: Move history into InputProvider logic?
            // For now, provider.resolve(Target) handles saving history.
            let target = match input.resolve(&ToolInput::Target) {
                Some(t) => t,
                None => return,
            };

            let run_bg = input.confirm_background();
            // Legacy configure still needs IO for profile selection (refactor needed later)
            let config = nmap::configure_nmap(&target, None, false, None, &*executor, io);

            run_tool_workflow(
                Some(config),
                use_proxy,
                executor,
                io,
                job_manager,
                |cfg, p, ex, i, job| nmap::execute_nmap_scan(cfg, p, &*ex, i, job),
                |cfg| format!("Nmap {}", cfg.target),
                run_bg,
            );
        }
        SpecializedStrategy::WebEnum => {
            let target = match input.resolve(&ToolInput::Target) {
                Some(t) => t,
                None => return,
            };
            let run_bg = input.confirm_background();

            let config = web::configure_web_enum(&target, None, &*executor, io);
            run_tool_workflow(
                config,
                use_proxy,
                executor,
                io,
                job_manager,
                |cfg, p, ex, i, _job| web::execute_web_enum(cfg, p, &*ex, i),
                |cfg| format!("WebEnum {}", cfg.target),
                run_bg,
            );
        }
        SpecializedStrategy::Fuzzer => {
            let target = match input.resolve(&ToolInput::Text(
                "Enter Target URL (with FUZZ):".to_string(),
            )) {
                Some(t) => t,
                None => return,
            };
            let run_bg = input.confirm_background();

            let config = fuzzer::configure_fuzzer(&target, None, None, &*executor, io);
            run_tool_workflow(
                config,
                use_proxy,
                executor,
                io,
                job_manager,
                |cfg, p, ex, i, _job| fuzzer::execute_fuzzer(cfg, p, &*ex, i),
                |cfg| format!("Fuzzer {}", cfg.target),
                run_bg,
            );
        }
        SpecializedStrategy::ExploitActive => {
            let run_bg = input.confirm_background();
            let config = exploit::configure_exploitation("", None, None, &*executor, io);
            run_tool_workflow(
                config,
                use_proxy,
                executor,
                io,
                job_manager,
                |cfg, p, ex, i, _job| exploit::execute_exploitation(cfg, p, &*ex, i),
                |_cfg| "Exploitation Job".to_string(),
                run_bg,
            );
        }
        SpecializedStrategy::Poison => {
            let interface = match input.resolve(&ToolInput::Interface) {
                Some(i) => i,
                None => return,
            };
            let run_bg = input.confirm_background();

            let config = poison::configure_poisoning(&interface, &*executor, io);
            run_tool_workflow(
                config,
                use_proxy,
                executor,
                io,
                job_manager,
                |cfg, p, ex, i, _job| poison::execute_poisoning(cfg, p, &*ex, i),
                |cfg| format!("Poisoning {}", cfg.interface),
                run_bg,
            );
        }
        SpecializedStrategy::Wifi => {
            let interface = match input.resolve(&ToolInput::Interface) {
                Some(i) => i,
                None => return,
            };
            let run_bg = input.confirm_background();

            let config = wifi::configure_wifi(&interface, &*executor, io);
            run_tool_workflow(
                config,
                use_proxy,
                executor,
                io,
                job_manager,
                |cfg, p, ex, i, _job| wifi::execute_wifi_audit(cfg, p, &*ex, i),
                |cfg| format!("WifiAudit {}", cfg.interface),
                run_bg,
            );
        }
        SpecializedStrategy::Bluetooth => {
            let mac = input.resolve_text("Enter Target MAC (Optional):", Some(""));
            let run_bg = input.confirm_background();

            let config = bluetooth::configure_bluetooth(&mac.unwrap_or_default(), &*executor, io);
            run_tool_workflow(
                config,
                use_proxy,
                executor,
                io,
                job_manager,
                |cfg, p, ex, i, _job| bluetooth::execute_bluetooth(cfg, p, &*ex, i),
                |cfg| format!("Bluetooth {}", cfg.profile.name),
                run_bg,
            );
        }
    }
}

fn run_standard_tool(
    spec: &ToolSpecification,
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    tool_name: &str,
    input: &dyn InputProvider,
) {
    io.println(&format!(
        "{}",
        format!("[*] Running Tool: {}", tool_name).blue().bold()
    ));

    // Gather Inputs
    let mut args = spec.args_template.clone();

    for input_def in &spec.inputs {
        let (val, placeholder) = match input_def {
            ToolInput::Target | ToolInput::Interface | ToolInput::Wordlist | ToolInput::Text(_) => {
                let v = input.resolve(input_def);
                if v.is_none() {
                    return;
                }
                (
                    v.unwrap(),
                    match input_def {
                        ToolInput::Target => "{target}",
                        ToolInput::Interface => "{interface}",
                        ToolInput::Wordlist => "{wordlist}",
                        ToolInput::Text(_) => "{text}", // Naive placeholder for now
                        _ => "",
                    },
                )
            }
            ToolInput::None => (String::new(), ""),
        };

        if !placeholder.is_empty() {
            args = args.replace(placeholder, &val);
        }
    }

    let binary = spec.binary.clone();
    let final_args_str = args.clone();

    let run_bg = input.confirm_background();
    let requires_root = spec.requires_root;

    let task = move |_cfg: (),
                     _proxy: bool,
                     exec: &dyn CommandExecutor,
                     io: &dyn IoHandler,
                     job: Option<Arc<Job>>| {
        let arg_parts: Vec<&str> = final_args_str.split_whitespace().collect();
        io.println(&format!("[+] Executing: {} {}", binary, final_args_str));

        let cancellation_token = job.as_ref().map(|j| j.cancelled.clone());

        let res = if requires_root && !exec.is_root() {
            let mut sudo_args = vec![binary.as_str()];
            sudo_args.extend(arg_parts);
            exec.execute_cancellable("sudo", &sudo_args, "", cancellation_token)
        } else {
            exec.execute_cancellable(&binary, &arg_parts, "", cancellation_token)
        };

        match res {
            Ok(s) => {
                if !s.success() {
                    io.println(&format!("{}", "[!] Tool exited with error.".red()));
                }
            }
            Err(e) => io.println(&format!("{} {}", "[!] Execution failed:".red(), e)),
        }
    };

    let name = tool_name.to_string();
    run_tool_workflow(
        Some(()),
        use_proxy,
        executor,
        io,
        job_manager,
        task,
        move |_| name.clone(),
        run_bg,
    );
}

fn add_custom_tool_flow(io: &dyn IoHandler, input: &dyn InputProvider) {
    ui::clear_screen();
    ui::print_header(io, "Custom Toolbox", Some("Add New Tool"));

    io.println(&format!(
        "{}",
        "Define a new user tool (saved to file).".yellow()
    ));
    let name = input.resolve_text("Tool Name:", None);
    if name.is_none() {
        return;
    }

    let binary = input
        .resolve_text("Binary/Command:", None)
        .unwrap_or_default();
    let args = input
        .resolve_text("Arguments Template:", None)
        .unwrap_or_default();

    io.println("\n[!] Saving tool definition... (Simulated)");

    let tool = ToolSpecification::new(&binary, &args, vec![ToolInput::Target]);

    if let Ok(json) = serde_json::to_string_pretty(&tool) {
        io.println(&format!(
            "Saved Config for '{}':\n{}",
            name.as_ref().unwrap(),
            json.cyan()
        ));
        let _ = fs::write(
            format!("custom_{}.json", name.unwrap().replace(' ', "_")),
            json,
        );
    }

    io.print("\nTool added! Press Enter to return...");
    io.flush();
    let _ = io.read_line();
}

fn custom_tools_category(
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    input: &dyn InputProvider,
) {
    let tools = vec![Tool::add_placeholder()];
    show_submenu(
        "Custom Toolbox",
        tools,
        use_proxy,
        executor,
        io,
        job_manager,
        input,
    );
}

// --- Categories ---

fn recon_category(
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    input: &dyn InputProvider,
) {
    let tools = vec![Tool::core_specialized(
        "Nmap Automator (Standard)",
        "Automated Nmap Scans",
        SpecializedStrategy::Nmap,
    )];
    show_submenu(
        "Network Recon",
        tools,
        use_proxy,
        executor,
        io,
        job_manager,
        input,
    );
}

fn web_category(
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    input: &dyn InputProvider,
) {
    let tools = vec![
        Tool::core_specialized(
            "Web Enumeration - Gobuster",
            "Directory Brute-forcing",
            SpecializedStrategy::WebEnum,
        ),
        Tool::core_specialized(
            "Web Fuzzing - Ffuf",
            "Web Fuzzing",
            SpecializedStrategy::Fuzzer,
        ),
    ];
    show_submenu(
        "Web Arsenal",
        tools,
        use_proxy,
        executor,
        io,
        job_manager,
        input,
    );
}

fn exploit_category(
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    input: &dyn InputProvider,
) {
    let tools = vec![
        Tool::core_standard(
            "Exploit Search - Searchsploit",
            "Search Exploit-DB",
            ToolSpecification::new(
                "searchsploit",
                "{query}",
                vec![ToolInput::Text("Enter Search Query: ".to_string())],
            ),
        ),
        Tool::core_specialized(
            "Active Exploitation (SQLMap, Curl, Hydra)",
            "Active Attacks",
            SpecializedStrategy::ExploitActive,
        ),
    ];
    show_submenu(
        "Exploitation Hub",
        tools,
        use_proxy,
        executor,
        io,
        job_manager,
        input,
    );
}

fn netops_category(
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    input: &dyn InputProvider,
) {
    let tools = vec![
        Tool::core_standard(
            "Packet Sniffer - Tcpdump",
            "Packet capture",
            ToolSpecification::new("tcpdump", "-i {interface} -v", vec![ToolInput::Interface])
                .require_root(),
        ),
        Tool::core_specialized(
            "LAN Poisoning - Responder",
            "LLMNR Poisoner",
            SpecializedStrategy::Poison,
        ),
    ];
    show_submenu(
        "Network Operations",
        tools,
        use_proxy,
        executor,
        io,
        job_manager,
        input,
    );
}

fn wireless_category(
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    input: &dyn InputProvider,
) {
    let tools = vec![
        Tool::core_specialized(
            "WiFi Audit - Wifite",
            "Wireless Auditing",
            SpecializedStrategy::Wifi,
        ),
        Tool::core_specialized(
            "Bluetooth Arsenal",
            "Bluetooth Attacks",
            SpecializedStrategy::Bluetooth,
        ),
    ];
    show_submenu(
        "Wireless & RF",
        tools,
        use_proxy,
        executor,
        io,
        job_manager,
        input,
    );
}

fn show_submenu(
    title: &str,
    tools: Vec<Tool>,
    use_proxy: bool,
    executor: Arc<dyn CommandExecutor + Send + Sync>,
    io: &dyn IoHandler,
    job_manager: Option<Arc<JobManager>>,
    input: &dyn InputProvider,
) {
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
        if choice_str.trim().is_empty() {
            break;
        }
        let choice_idx = choice_str.trim().parse::<usize>().unwrap_or(99);

        if choice_idx == 0 {
            break;
        }

        if choice_idx > 0 && choice_idx <= tools.len() {
            let tool = &tools[choice_idx - 1];
            run_tool_dispatch(
                tool,
                use_proxy,
                executor.clone(),
                io,
                job_manager.clone(),
                input,
            );
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        }
    }
}

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
    F: Fn(C, bool, &dyn CommandExecutor, &dyn IoHandler, Option<Arc<Job>>) + Send + Sync + 'static,
    N: Fn(&C) -> String + Send + Sync + 'static,
{
    if let Some(cfg) = config {
        if run_bg {
            if let Some(jm) = job_manager {
                let name = name_gen(&cfg);
                let task_arc = Arc::new(task);
                let task_clone = task_arc.clone();
                let cfg_arc = Arc::new(cfg);

                jm.spawn_job(
                    &name,
                    move |ex, i, job| {
                        let c = cfg_arc.clone();
                        task_clone((*c).clone(), use_proxy, &*ex, i, Some(job));
                    },
                    executor,
                    true,
                );

                io.println(&format!(
                    "{}",
                    format!("Job '{}' started in background.", name).green()
                ));
            } else {
                io.println(&format!("{}", "[!] Job Manager not available.".red()));
                task(cfg, use_proxy, &*executor, io, None);
                io.print("\nPress Enter to return to menu...");
                io.flush();
                let _ = io.read_line();
            }
        } else {
            // Foreground
            task(cfg, use_proxy, &*executor, io, None);
            io.print("\nPress Enter to return to menu...");
            io.flush();
            let _ = io.read_line();
        }
    }
}

fn main() {
    let _ = ctrlc::set_handler(move || {
        println!("\n{}", "^C Received".dimmed());
    });

    let cli = Cli::parse();

    // Determine configuration based on command or global args
    let (container_mode, image_name, serve_port) = match &cli.command {
        Some(Commands::Serve {
            port,
            container,
            image,
        }) => (*container, image.clone(), Some(*port)),
        _ => (cli.container, cli.image.clone(), None),
    };

    let executor: Arc<dyn CommandExecutor + Send + Sync> = if container_mode {
        Arc::new(HybridExecutor::new(&image_name))
    } else {
        Arc::new(ShellExecutor)
    };

    let io = RealIoHandler;
    let job_manager = Arc::new(JobManager::new());
    let use_proxy = cli.proxy;

    if let Some(port) = serve_port {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(api::serve(port, job_manager, executor));
        return;
    }

    if let Some(Commands::History) = cli.command {
        print_history(&io);
        return;
    }

    if let Some(target) = &cli.nmap {
        if let Err(e) = validation::validate_target(target) {
            io.println(&format!("{} {}", "[!] Invalid Target:".red(), e));
            return;
        }
        if let Some(args) = &cli.args {
            let parts: Vec<String> = args.split_whitespace().map(|s| s.to_string()).collect();
            if let Err(e) = validation::validate_nmap_flags(&parts) {
                io.println(&format!("{} {}", "[!] Invalid Arguments:".red(), e));
                return;
            }
        }
        nmap::run_nmap_scan(
            target,
            cli.port.as_deref(),
            cli.no_ping,
            cli.args.as_deref(),
            use_proxy,
            &*executor,
            &io,
        );
        return;
    }

    if let Some(interface) = cli.wifite {
        // Interface validation (basic check)
        if interface.contains(';') || interface.contains('|') {
            io.println(&format!("{}", "[!] Invalid Interface name.".red()));
            return;
        }
        wifi::run_wifi_audit(&interface, use_proxy, &*executor, &io);
        return;
    }

    if let Some(interface) = cli.sniff {
        if interface.contains(';') || interface.contains('|') {
            io.println(&format!("{}", "[!] Invalid Interface name.".red()));
            return;
        }
        sniffer::run_sniffer(&interface, use_proxy, &*executor, &io);
        return;
    }

    if let Some(target) = &cli.web {
        if let Err(e) = validation::validate_target(target) {
            io.println(&format!("{} {}", "[!] Invalid Target:".red(), e));
            return;
        }
        web::run_web_enum(target, cli.args.as_deref(), use_proxy, &*executor, &io);
        return;
    }

    if let Some(target) = &cli.fuzz {
        // Fuzz target might contain FUZZ keyword, but base URL should be valid?
        // Or we loosen validation for Fuzzing. validate_target allows URLs.
        // Let's rely on basic shell char check for now.
        if target.contains(';') || target.contains('|') {
            io.println(&format!("{}", "[!] Invalid Target.".red()));
            return;
        }
        fuzzer::run_fuzzer(
            target,
            cli.wordlist.as_deref(),
            cli.args.as_deref(),
            use_proxy,
            &*executor,
            &io,
        );
        return;
    }

    if let Some(target) = &cli.brute {
        if let Err(e) = validation::validate_target(target) {
            io.println(&format!("{} {}", "[!] Invalid Target:".red(), e));
            return;
        }
        brute::run_brute_force(target, use_proxy, &*executor, &io);
        return;
    }

    if let Some(target) = &cli.search_exploit {
        // Search query might be loose text, but shouldn't have shell chars
        if target.contains(';') || target.contains('|') {
            io.println(&format!("{}", "[!] Invalid Search Query.".red()));
            return;
        }
        search_exploit::run_searchsploit(target, use_proxy, &*executor, &io);
        return;
    }

    if let Some(target) = &cli.exploit {
        if let Err(e) = validation::validate_target(target) {
            io.println(&format!("{} {}", "[!] Invalid Target:".red(), e));
            return;
        }
        exploit::run_exploitation_tool(
            target,
            cli.tool.as_deref(),
            cli.args.as_deref(),
            use_proxy,
            &*executor,
            &io,
        );
        return;
    }

    if let Some(interface) = &cli.poison {
        if interface.contains(';') || interface.contains('|') {
            io.println(&format!("{}", "[!] Invalid Interface.".red()));
            return;
        }
        poison::run_poisoning(interface, use_proxy, &*executor, &io);
        return;
    }

    if let Some(arg) = &cli.bluetooth {
        if arg.contains(';') || arg.contains('|') {
            io.println(&format!("{}", "[!] Invalid Argument.".red()));
            return;
        }
        bluetooth::run_bluetooth_attacks(arg, use_proxy, &*executor, &io);
        return;
    }

    run_interactive_mode(use_proxy, executor, &io, job_manager);
}
