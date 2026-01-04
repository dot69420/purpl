#[cfg(test)]
mod tests {
    use crate::{Cli, Commands, Tool, print_banner, run_legacy_script, run_interactive_mode};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;
    use clap::CommandFactory;
    use clap::Parser;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn test_cli_parsing_nmap() {
        let cli = Cli::try_parse_from(&["nt_test", "--nmap", "127.0.0.1"]).unwrap();
        assert_eq!(cli.nmap, Some("127.0.0.1".to_string()));
        assert!(!cli.proxy);
    }

    #[test]
    fn test_cli_parsing_proxy() {
        let cli = Cli::try_parse_from(&["nt_test", "--proxy"]).unwrap();
        assert!(cli.proxy);
    }

    #[test]
    fn test_cli_parsing_subcommand() {
        let cli = Cli::try_parse_from(&["nt_test", "history"]).unwrap();
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
        assert!(out.contains("NT_TEST Control Center"));
    }

    #[test]
    fn test_run_legacy_script_sudo() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        executor.add_status(ExitStatusExt::from_raw(0));

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

        executor.add_status(ExitStatusExt::from_raw(0));

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

        // 8 tools.
        // 9: Scan Results
        // 10: History
        // 11: Toggle Proxy
        // 12: Exit

        io.add_input("12\n");

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

        // Back in loop. Select 12 (Exit)
        io.add_input("12\n");

        // Mock nmap host discovery output
        use std::process::Output;
        executor.add_output(Output {
            status: ExitStatusExt::from_raw(0),
            stdout: b"Nmap scan report for 127.0.0.1".to_vec(),
            stderr: Vec::new(),
        });

        run_interactive_mode(false, &executor, &io);

        let calls = executor.get_calls();
        assert!(!calls.is_empty());
        assert_eq!(calls[0].command, "nmap");
    }
}
