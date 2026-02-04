#[cfg(test)]
mod tests {
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;
    use crate::web::{WebProfile, build_gobuster_command, run_web_enum};

    #[test]
    fn test_run_web_enum_logic() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        // Mock 1: gobuster version check success
        executor.register_output("gobuster", b"Gobuster v3.0");

        // Input: "1" (select first profile)
        io.add_input("1\n");
        // Input: Wordlist path (needed if manual is selected, which is likely default in test env)
        // Use /dev/null as a valid existing file path.
        io.add_input("/dev/null\n");

        run_web_enum("http://example.com", None, false, &executor, &io);

        let calls = executor.get_calls();
        // 1. version check
        // 2. execution (only if wordlist was found)
        assert!(calls.len() >= 2);
        assert_eq!(calls[0].args, vec!["version"]);
    }

    #[test]
    fn test_build_gobuster_command_basic() {
        let flags = vec!["-t", "50"];
        let (cmd, args) = build_gobuster_command(
            "gobuster",
            "http://test.com",
            "wordlist.txt",
            "out.txt",
            &flags,
            false,
        );

        assert_eq!(cmd, "gobuster");
        // dir -u <url> -w <wordlist> -o <out> <flags>
        assert_eq!(args[0], "dir");
        assert!(args.contains(&"http://test.com".to_string()));
        assert!(args.contains(&"wordlist.txt".to_string()));
        assert!(args.contains(&"out.txt".to_string()));
    }

    #[test]
    fn test_build_gobuster_command_proxy() {
        let flags = vec!["-t", "50"];
        let (cmd, args) = build_gobuster_command(
            "gobuster",
            "http://test.com",
            "wordlist.txt",
            "out.txt",
            &flags,
            true,
        );

        assert_eq!(cmd, "proxychains");
        assert_eq!(args[0], "gobuster");
    }

    #[test]
    fn test_web_profile_new() {
        let profile = WebProfile::new("Test", "Desc", "wl", &["-a"]);
        assert_eq!(profile.name, "Test");
        assert_eq!(profile.description, "Desc");
        assert_eq!(profile.wordlist, "wl");
        assert_eq!(profile.flags, vec!["-a"]);
    }
}
