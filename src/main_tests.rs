#[cfg(test)]
mod tests {
    use crate::{Cli, Commands, Tool, print_banner, run_legacy_script, run_interactive_mode};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;
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
    fn test_print_banner() {
        let io = MockIoHandler::new();
        print_banner(&io);
        let out = io.get_output();
        assert!(out.contains("PURPL Control Center"));
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
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();
        io.add_input("14\n");

        run_interactive_mode(false, &executor, &io);

        let out = io.get_output();
        assert!(out.contains("Exiting"));
    }

    #[test]
    fn test_run_interactive_mode_select_tool() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        // 1. Select Tool 1 (Nmap)
        io.add_input("1\n");

        // Tool 1 needs arg: "Enter target IP or Range: "
        io.add_input("127.0.0.1\n");

        // Then inside tool logic:
        // Nmap tool uses run_nmap_scan.
        // It asks for Profile (Input 2)
        io.add_input("2\n");

        // After tool runs, menu asks "Press Enter to return..."
        io.add_input("\n");

        io.add_input("14\n");

        // Mock nmap host discovery output using new registry
        executor.register_output("nmap", b"Nmap scan report for 127.0.0.1");

        run_interactive_mode(false, &executor, &io);

        let calls = executor.get_calls();
        assert!(!calls.is_empty());
        
        let cmds: Vec<String> = calls.iter().map(|c| c.command.clone()).collect();
        assert!(cmds.contains(&"nmap".to_string()));
    }
    
    #[test]
    fn test_interactive_mode_full_flow() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();
        
        // --- Setup Mocks (Robust Rule-Based) ---
        // By default MockExecutor returns success, but let's be explicit for tools we care about
        executor.register_success("nmap");
        executor.register_success("gobuster");
        executor.register_success("hydra");
        executor.register_success("responder");
        executor.register_success("bluetoothctl");
        executor.register_success("tcpdump");
        
        // --- Sequence of Inputs ---

        // 1. Nmap (Option 1)
        io.add_input("1\n"); // Select Nmap
        io.add_input("10.0.0.1\n"); // Target
        io.add_input("2\n"); // Profile: Quick
        io.add_input("\n"); // Return to menu

        // 2. Web (Option 2)
        io.add_input("2\n"); // Select Web
        io.add_input("http://10.0.0.1\n"); // Target
        io.add_input("3\n"); // Profile: Manual
        io.add_input("wordlists/test.txt\n"); // Wordlist path (will fail check but won't crash)
        io.add_input("\n"); // Return to menu

        // 3. Brute (Option 6)
        io.add_input("6\n"); // Select Brute
        io.add_input("10.0.0.1\n"); // Target
        io.add_input("1\n"); // Protocol: ssh
        io.add_input("3\n"); // Profile: Manual
        io.add_input("users.txt\n"); // User list
        io.add_input("pass.txt\n"); // Pass list
        io.add_input("\n"); // Return to menu

        // 4. Poison (Option 7)
        io.add_input("7\n"); // Select Poison
        io.add_input("eth0\n"); // Interface
        io.add_input("1\n"); // Profile: Analyze
        io.add_input("\n"); // Return to menu

        // 5. Bluetooth (Option 10)
        io.add_input("10\n"); // Select Bluetooth
        io.add_input("\n"); // Target MAC (Empty)
        io.add_input("1\n"); // Profile: Scan
        io.add_input("\n"); // Return to menu

        // 6. Sniffer (Option 9)
        io.add_input("9\n"); // Select Sniffer
        io.add_input("eth0\n"); // Interface
        io.add_input("4\n"); // Profile: ICMP
        io.add_input("\n"); // Return to menu

        // 7. Exit
        io.add_input("14\n");

        // --- Run ---
        run_interactive_mode(false, &executor, &io);

        // --- Verification ---
        let calls = executor.get_calls();
        let commands: Vec<String> = calls.iter().map(|c| c.command.clone()).collect();
        
        // Debug
        // println!("Executed commands: {:?}", commands);

        // Assertions
        assert!(commands.contains(&"nmap".to_string()), "Nmap should have been called");
        // Gobuster might be skipped if wordlist check fails logic inside web.rs, 
        // but verify at least the attempt (version check) if implemented, or menu flow valid.
        // Actually web.rs checks `executor.execute_output("gobuster", &["version"])` first.
        assert!(commands.contains(&"gobuster".to_string()), "Gobuster version check should have occurred");
        
        assert!(commands.contains(&"hydra".to_string()), "Hydra should have been called");
        assert!(commands.contains(&"responder".to_string()), "Responder should have been called");
        assert!(commands.contains(&"bluetoothctl".to_string()), "Bluetoothctl should have been called");
        assert!(commands.contains(&"tcpdump".to_string()), "Tcpdump should have been called");
    }
}