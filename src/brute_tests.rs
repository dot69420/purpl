#[cfg(test)]
mod tests {
    use crate::brute::{run_brute_force, build_hydra_command, BruteProfile};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;


    #[test]
    fn test_run_brute_force_logic() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        // Mock 1: hydra check success
        executor.register_success("hydra");

        // Input: "1" (Select first protocol - e.g., SSH)
        io.add_input("1\n");
        // Input: "1" (Select first profile - e.g., Fast)
        io.add_input("1\n");

        run_brute_force("127.0.0.1", false, &executor, &io);

        let calls = executor.get_calls();
        assert!(calls.len() >= 2);
        // Corrected expectation: hydra uses -h, not --help often, but code uses -h.
        assert_eq!(calls[0].args, vec!["-h"]);
    }

    #[test]
    fn test_build_hydra_command_basic() {
        let flags = vec!["-t", "4"];
        let (cmd, args) = build_hydra_command(
            "hydra",
            &flags,
            "-L", "users.txt",
            "-P", "pass.txt",
            "out.txt",
            "192.168.1.1",
            "ssh",
            false
        );

        assert_eq!(cmd, "hydra");
        assert!(args.contains(&"-L".to_string()));
        assert!(args.contains(&"users.txt".to_string()));
        assert!(args.contains(&"192.168.1.1".to_string()));
        assert!(args.contains(&"ssh".to_string()));
    }

    #[test]
    fn test_build_hydra_command_proxy() {
        let flags = vec!["-v"];
        let (cmd, args) = build_hydra_command(
            "hydra",
            &flags,
            "-l", "admin",
            "-P", "pass.txt",
            "out.txt",
            "10.0.0.1",
            "ftp",
            true
        );

        assert_eq!(cmd, "proxychains");
        assert_eq!(args[0], "hydra");
        assert!(args.contains(&"-l".to_string()));
        assert!(args.contains(&"admin".to_string()));
    }

    #[test]
    fn test_brute_profile_new() {
        let profile = BruteProfile::new("Test", "Desc", "u", "p", &["-f"]);
        assert_eq!(profile.name, "Test");
        assert_eq!(profile.description, "Desc");
        assert_eq!(profile.userlist, "u");
        assert_eq!(profile.passlist, "p");
        assert_eq!(profile.flags, vec!["-f"]);
    }
}
