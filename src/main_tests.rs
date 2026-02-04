#[cfg(test)]
mod tests {
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;
    use crate::job_manager::JobManager;
    use crate::tool_model::{SpecializedStrategy, Tool, ToolImplementation, ToolSource};
    use crate::{Cli, Commands, run_interactive_mode};
    use clap::CommandFactory;
    use clap::Parser;
    use std::fs;
    use std::sync::Arc;

    #[test]
    fn test_cli_parsing_nmap() {
        let cli = Cli::try_parse_from(&["purpl", "--nmap", "127.0.0.1"]).unwrap();
        assert_eq!(cli.nmap, Some("127.0.0.1".to_string()));
        assert!(!cli.proxy);
    }

    #[test]
    fn test_cli_parsing_proxy() {
        let cli = Cli::try_parse_from(&["purpl", "--proxy"]).unwrap();
        assert!(cli.proxy);
    }

    #[test]
    fn test_cli_parsing_subcommand() {
        let cli = Cli::try_parse_from(&["purpl", "history"]).unwrap();
        assert_eq!(cli.command, Some(Commands::History));
    }

    #[test]
    fn test_tool_creation() {
        let tool = Tool::core_specialized("Test", "Desc", SpecializedStrategy::Nmap);
        assert_eq!(tool.name, "Test");
        match tool.implementation {
            ToolImplementation::Specialized(SpecializedStrategy::Nmap) => assert!(true),
            _ => assert!(false),
        }
        match tool.source {
            ToolSource::Core => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_print_banner() {
        let io = MockIoHandler::new();
        crate::ui::print_main_menu_banner(&io);
        let out = io.get_output();
        assert!(out.contains("Purple Team Helper Tool"));
    }

    #[test]
    fn test_run_interactive_mode_exit() {
        let executor = Arc::new(MockExecutor::new());
        let io = MockIoHandler::new();
        let job_manager = Arc::new(JobManager::new());
        // Exit is option 0
        io.add_input("0\n");

        run_interactive_mode(false, executor.clone(), &io, job_manager);

        let out = io.get_output();
        assert!(out.contains("Exiting"));
    }

    #[test]
    fn test_run_interactive_mode_select_tool() {
        let executor = Arc::new(MockExecutor::new());
        let io = MockIoHandler::new();
        let job_manager = Arc::new(JobManager::new());

        // 1. Select Tool 1 (Network Recon Category)
        io.add_input("1\n");

        // 2. Select Tool 1 (Nmap Automator) inside Submenu
        io.add_input("1\n");

        // 3. Tool needs arg: "Enter target IP: "
        io.add_input("127.0.0.1\n");

        // 4. Background prompt (New logic: Target -> BG -> Profile)
        io.add_input("n\n");

        // 5. Nmap Profile Selection (Input 2)
        io.add_input("2\n");

        // 6. After tool runs, submenu asks "Press Enter to return to menu..."
        io.add_input("\n");

        // 7. Back to Main Menu (Option 0 in Submenu)
        io.add_input("0\n");

        // 8. Exit (Option 0 in Main Menu)
        io.add_input("0\n");

        // Mock nmap host discovery output using new registry
        executor.register_output("nmap", b"Nmap scan report for 127.0.0.1");

        run_interactive_mode(false, executor.clone(), &io, job_manager);

        let calls = executor.get_calls();
        assert!(!calls.is_empty());

        let cmds: Vec<String> = calls.iter().map(|c| c.command.clone()).collect();
        assert!(cmds.contains(&"nmap".to_string()));
    }

    #[test]
    fn test_interactive_mode_full_flow() {
        // Ensure wordlists/common.txt exists for Quick Scan profile
        let _ = fs::create_dir_all("wordlists");
        let _ = fs::write("wordlists/common.txt", "test");

        let executor = Arc::new(MockExecutor::new());
        let io = MockIoHandler::new();
        let job_manager = Arc::new(JobManager::new());

        // --- Setup Mocks ---
        executor.register_success("nmap");
        executor.register_success("gobuster");
        executor.register_success("responder");
        executor.register_success("tcpdump");
        // Mock sudo call for sniffer if it asks (it shouldn't if root, but test executor mimics non-root usually? MockExecutor has is_root() -> true by default).
        // If is_root() is true, it won't ask sudo.

        executor.register_output("ip", b"1: lo: <LOOPBACK...\n>2: eth0: <BROADCAST...>");

        // --- Sequence of Inputs ---

        // 1. Network Recon (Option 1) -> Nmap (Option 1)
        io.add_input("1\n"); // Select Recon Category
        io.add_input("1\n"); // Select Nmap
        io.add_input("10.0.0.1\n"); // Target
        io.add_input("n\n"); // Background: No (NEW ORDER)
        io.add_input("2\n"); // Profile: Quick
        io.add_input("\n"); // Return to submenu
        io.add_input("\n"); // EXTRA
        io.add_input("0\n"); // Back to Main Menu

        // 2. Web Arsenal (Option 2) -> Gobuster (Option 1)
        io.add_input("2\n"); // Enter Web Submenu
        io.add_input("1\n"); // Select Gobuster
        io.add_input("http://10.0.0.1\n"); // Target
        io.add_input("n\n"); // Background: No (NEW POSITION)
        io.add_input("1\n"); // Profile 1: Quick Scan
        io.add_input("\n"); // Press Enter to return
        io.add_input("\n"); // EXTRA
        io.add_input("0\n"); // Back to Main Menu

        // 3. Network Ops (Option 4) -> Sniffer (Option 1 - Core Standard)
        io.add_input("4\n"); // Enter NetOps Submenu
        io.add_input("1\n"); // Select Sniffer
        // Standard Tool Flow: Inputs -> BG -> Run
        io.add_input("eth0\n"); // Interface Input
        io.add_input("n\n"); // Background: No
        io.add_input("\n"); // Press Enter to return
        io.add_input("\n"); // EXTRA
        io.add_input("0\n"); // Back to Main Menu

        // 4. Exit (Option 0)
        io.add_input("0\n");

        // --- Run ---
        run_interactive_mode(false, executor.clone(), &io, job_manager);

        // --- Verification ---
        let calls = executor.get_calls();
        let commands: Vec<String> = calls.iter().map(|c| c.command.clone()).collect();

        assert!(
            commands.contains(&"nmap".to_string()),
            "Nmap should have been called"
        );
        assert!(
            commands.contains(&"gobuster".to_string()),
            "Gobuster should have been called"
        );
        assert!(
            commands.contains(&"tcpdump".to_string()),
            "Tcpdump should have been called"
        );
    }
}
