#[cfg(test)]
mod tests {
    use crate::nmap::{build_nmap_command, ScanProfile, run_nmap_scan};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;


    #[test]
    fn test_run_nmap_scan_logic() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        // 1. Host Discovery Output
        executor.register_output("nmap", b"Starting Nmap...");

        // Input: Select Profile ("2")
        io.add_input("2\n");

        run_nmap_scan("192.168.1.1", None, false, None, false, &executor, &io);

        let calls = executor.get_calls();
        assert!(calls.len() >= 1);
        assert_eq!(calls[0].command, "nmap");
        assert!(calls[0].args.contains(&"-sn".to_string())); // Host discovery args

        let out = io.get_output();
        assert!(out.contains("Select Scan Profile"));
        assert!(out.contains("No alive hosts found")); // Expected because file wasn't written
    }

    #[test]
    fn test_build_nmap_command_basic() {
        let flags = vec!["-sS", "-sV"];
        let target = "192.168.1.1";
        let output_file = "output";
        let (cmd, args) = build_nmap_command("nmap", &flags, target, output_file, false, false);

        assert_eq!(cmd, "nmap");
        assert_eq!(args, vec!["-sS", "-sV", "192.168.1.1", "-oA", "output"]);
    }

    #[test]
    fn test_build_nmap_command_proxy() {
        let flags = vec!["-sS"];
        let target = "10.0.0.1";
        let output_file = "";
        let (cmd, args) = build_nmap_command("nmap", &flags, target, output_file, true, false);

        assert_eq!(cmd, "proxychains");
        assert_eq!(args, vec!["nmap", "-sS", "10.0.0.1"]);
    }

    #[test]
    fn test_build_nmap_command_sudo() {
        let flags = vec!["-O"];
        let target = "localhost";
        let output_file = "test";
        let (cmd, args) = build_nmap_command("nmap", &flags, target, output_file, false, true);

        assert_eq!(cmd, "sudo");
        assert_eq!(args, vec!["nmap", "-O", "localhost", "-oA", "test"]);
    }

    #[test]
    fn test_build_nmap_command_sudo_proxy() {
        let flags = vec!["-A"];
        let target = "scanme.nmap.org";
        let output_file = "scanme";
        let (cmd, args) = build_nmap_command("nmap", &flags, target, output_file, true, true);

        // Order: sudo proxychains nmap ...
        assert_eq!(cmd, "sudo");
        assert_eq!(args[0], "proxychains");
        assert_eq!(args[1], "nmap");
        assert!(args.contains(&"-A".to_string()));
    }

    #[test]
    fn test_scan_profile_new() {
        let profile = ScanProfile::new("Test", "Desc", &["-a", "-b"], true);
        assert_eq!(profile.name, "Test");
        assert_eq!(profile.description, "Desc");
        assert_eq!(profile.flags, vec!["-a", "-b"]);
        assert!(profile.requires_root);
    }
}
