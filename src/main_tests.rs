#[cfg(test)]
mod tests {
    use crate::{Cli, Commands, Tool, run_legacy_script, run_interactive_mode};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;
    use crate::job_manager::JobManager;
    use std::sync::Arc;
    use clap::CommandFactory;
    use clap::Parser;


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
        let tool = Tool::new("Test", "script.sh", true, "Arg:", false, None);
        assert_eq!(tool.name, "Test");
        assert_eq!(tool.script, "script.sh");
        assert!(tool.needs_arg);
        assert_eq!(tool.arg_prompt, "Arg:");
        assert!(!tool.use_sudo);
        assert!(tool.function.is_none());
    }

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_run_legacy_script_sudo() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        // Input: Enter to continue
        io.add_input("\n");

        run_legacy_script("myscript.sh", "arg1", true, &executor, &io);

        let calls = executor.get_calls();
        assert!(calls.len() >= 1);
        assert_eq!(calls[0].command, "sudo");
        assert!(calls[0].args.contains(&"./myscript.sh".to_string()));
        assert!(calls[0].args.contains(&"arg1".to_string()));
    }

    #[test]
    fn test_run_legacy_script_no_sudo() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        io.add_input("\n");

        run_legacy_script("myscript.sh", "arg1", false, &executor, &io);

        let calls = executor.get_calls();
        assert!(calls.len() >= 1);
        assert_eq!(calls[0].command, "./myscript.sh");
        assert!(calls[0].args.contains(&"arg1".to_string()));
    }

    #[test]
    fn test_run_interactive_mode_exit() {
        let executor = Arc::new(MockExecutor::new());
        let io = MockIoHandler::new();
        let job_manager = Arc::new(JobManager::new());
        // Exit is now option 8 (5 tools + 3 options)
        io.add_input("8\n");

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

        // 4. Nmap Profile Selection (Input 2)
        io.add_input("2\n");

        // 5. After tool runs, submenu asks "Press Enter to return to menu..."
        io.add_input("\n");

        // 6. Back to Main Menu (Option 0 in Submenu)
        io.add_input("0\n");

        // 7. Exit (Option 9 in Main Menu)
        io.add_input("9\n"); 

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
        let executor = Arc::new(MockExecutor::new());
        let io = MockIoHandler::new();
        let job_manager = Arc::new(JobManager::new());
        
        // --- Setup Mocks ---
        executor.register_success("nmap");
        executor.register_success("gobuster");
        executor.register_success("responder");
        executor.register_success("tcpdump");
        executor.register_output("ip", b"1: lo: <LOOPBACK...>\n2: eth0: <BROADCAST...>"); 
        
        // --- Sequence of Inputs ---

        // 1. Network Recon (Option 1) -> Nmap (Option 1)
        io.add_input("1\n"); // Select Recon Category
        io.add_input("1\n"); // Select Nmap
        io.add_input("10.0.0.1\n"); // Target
        io.add_input("n\n"); // Background: No
        io.add_input("2\n"); // Profile: Quick
        io.add_input("\n"); // Return to submenu
        io.add_input("0\n"); // Back to Main Menu

        // 2. Web Arsenal (Option 2) -> Gobuster (Option 1)
        io.add_input("2\n"); // Enter Web Submenu
        io.add_input("1\n"); // Select Gobuster
        io.add_input("http://10.0.0.1\n"); // Target
        io.add_input("3\n"); // Profile: Manual
        io.add_input("wordlists/test.txt\n"); // Wordlist
        io.add_input("n\n"); // Background: No
        io.add_input("\n"); // Press Enter to return
        io.add_input("0\n"); // Back to Main Menu

        // 3. Network Ops (Option 4) -> Sniffer (Option 1)
        io.add_input("4\n"); // Enter NetOps Submenu
        io.add_input("1\n"); // Select Sniffer
        io.add_input("1\n"); // Interface Selection (1: eth0)
        io.add_input("4\n"); // Profile: ICMP
        io.add_input("1\n"); // Mode: Passive
        io.add_input("n\n"); // Background: No
        io.add_input("\n"); // Press Enter to return
        io.add_input("0\n"); // Back to Main Menu

        // 4. Exit (Option 8)
        io.add_input("8\n");

        // --- Run ---
        run_interactive_mode(false, executor.clone(), &io, job_manager);

        // --- Verification ---
        let calls = executor.get_calls();
        let commands: Vec<String> = calls.iter().map(|c| c.command.clone()).collect();
        
        assert!(commands.contains(&"nmap".to_string()), "Nmap should have been called");
        assert!(commands.contains(&"gobuster".to_string()), "Gobuster should have been called");
        assert!(commands.contains(&"tcpdump".to_string()), "Tcpdump should have been called");
    }
}