#[cfg(test)]
mod tests {
    use crate::sniffer::{build_sniffer_command, SniffProfile, run_sniffer};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;


    #[test]
    fn test_run_sniffer_logic_root() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();
        // Default MockExecutor is root, so no prompt.

        // 1. Tcpdump output mock (stream)
        let output_data = "12:34:56.789000 IP 192.168.1.5 > 1.1.1.1: Flags [S]\nGET / HTTP/1.1\nHost: example.com\n";
        executor.register_output("tcpdump", output_data.as_bytes());

        // Input: Select Profile ("1")
        io.add_input("1\n");

        run_sniffer("eth0", false, &executor, &io);

        let calls = executor.get_calls();
        // Should have called tcpdump directly
        assert!(calls.len() >= 1);
        assert_eq!(calls[0].command, "tcpdump");

        let out = io.get_output();
        assert!(out.contains("Starting General Traffic"));
    }

    #[test]
    fn test_run_sniffer_logic_sudo() {
        let mut executor = MockExecutor::new();
        executor.set_root(false); // Not root
        let io = MockIoHandler::new();

        // 1. Register sudo success
        executor.register_success("sudo");
        
        // 2. Tcpdump output mock (stream) - command will be 'sudo' but args contain tcpdump
        // However, spawn_stdout is called on the *binary*.
        // If build_sniffer_command returns "sudo", then program is "sudo".
        // We need to register output for "sudo" or ensure logic handles it.
        // The mock executor registers by program name.
        let output_data = "12:34:56.789000 IP 192.168.1.5 > 1.1.1.1: Flags [S]\nGET / HTTP/1.1\nHost: example.com\n";
        executor.register_output("sudo", output_data.as_bytes());

        // Input 1: Prompt "Y" for sudo
        io.add_input("y\n");
        // Input 2: Select Profile ("1")
        io.add_input("1\n");

        run_sniffer("eth0", false, &executor, &io);

        let calls = executor.get_calls();
        // 1. sudo -v
        // 2. sudo tcpdump ...
        assert!(calls.len() >= 2);
        assert_eq!(calls[0].command, "sudo");
        assert_eq!(calls[0].args, vec!["-v"]);
        
        assert_eq!(calls[1].command, "sudo");
        assert_eq!(calls[1].args[0], "tcpdump");

        let out = io.get_output();
        assert!(out.contains("Starting General Traffic"));
    }

    #[test]
    fn test_build_sniffer_command_basic() {
        let args = vec!["-v", "-A"];
        let filter = "";
        let (cmd, args) = build_sniffer_command("tcpdump", "eth0", &args, filter, false);

        assert_eq!(cmd, "tcpdump");
        assert_eq!(args, vec!["-v", "-A", "-i", "eth0", "-l"]);
    }

    #[test]
    fn test_build_sniffer_command_filter() {
        let args = vec!["-v"];
        let filter = "tcp port 80";
        let (cmd, args) = build_sniffer_command("tcpdump", "wlan0", &args, filter, false);

        assert_eq!(cmd, "tcpdump");
        assert_eq!(args, vec!["-v", "-i", "wlan0", "-l", "tcp port 80"]);
    }

    #[test]
    fn test_build_sniffer_command_sudo() {
        let args = vec!["-v"];
        let filter = "";
        let (cmd, args) = build_sniffer_command("tcpdump", "eth0", &args, filter, true);

        assert_eq!(cmd, "sudo");
        assert_eq!(args[0], "tcpdump");
        assert_eq!(args[1], "-v");
        // ...
    }

    #[test]
    fn test_sniff_profile_new() {
        let profile = SniffProfile::new("Test", "Desc", "filter", &["-a"]);
        assert_eq!(profile.name, "Test");
        assert_eq!(profile.description, "Desc");
        assert_eq!(profile.filter, "filter");
        assert_eq!(profile.args, vec!["-a"]);
    }
}
