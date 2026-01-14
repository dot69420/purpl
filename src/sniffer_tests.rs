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

        // 1. ip link output mock
        executor.register_output("ip", b"1: lo: <LOOPBACK...>\n2: eth0: <BROADCAST...>");

        // 2. Tcpdump output mock (stream)
        let output_data = "12:34:56.789000 IP 192.168.1.5 > 1.1.1.1: Flags [S]\nGET / HTTP/1.1\nHost: example.com\n";
        executor.register_output("tcpdump", output_data.as_bytes());

        // Inputs:
        // 1. Interface Selection: "1" (eth0)
        // 2. Filter Selection: "1" (All Traffic)
        // 3. Mode Selection: "2" (Live Analysis)
        io.add_input("1\n");
        io.add_input("1\n");
        io.add_input("2\n");

        run_sniffer("", false, &executor, &io);

        let calls = executor.get_calls();
        
        // Expected calls:
        // 1. ip link show
        // 2. tcpdump ...
        assert!(calls.len() >= 2);
        
        let cmds: Vec<String> = calls.iter().map(|c| c.command.clone()).collect();
        assert!(cmds.contains(&"ip".to_string()));
        assert!(cmds.contains(&"tcpdump".to_string()));

        let out = io.get_output();
        assert!(out.contains("Starting All Traffic"));
    }

    #[test]
    fn test_run_sniffer_logic_sudo() {
        let mut executor = MockExecutor::new();
        executor.set_root(false); // Not root
        let io = MockIoHandler::new();

        // 1. Register sudo success
        executor.register_success("sudo");
        
        // 2. sudo ip link output
        executor.register_output("sudo", b"1: lo: <LOOPBACK...>\n2: eth0: <BROADCAST...>");
        
        // Note: For simplicity in mock, we reuse the output registry key "sudo" 
        // which might conflict if we need different outputs for "sudo -v", "sudo ip", "sudo tcpdump".
        // However, MockExecutor.register_output uses the *binary name*. 
        // Since all calls are "sudo", they share the output.
        // We can append the tcpdump data to the ip data to simulate stream if needed, 
        // OR rely on the fact that `execute_output` (for ip) reads stdout, and `spawn_stdout` (for tcpdump) reads stdout.
        // Let's combine them or register specifically. 
        // The MockExecutor implementation provided earlier uses a simple Map<String, Vec<u8>>.
        // It returns the SAME output every time for that binary.
        // So `sudo ip` gets the full blob, and `sudo tcpdump` gets the full blob.
        // `ip` parser ignores extra junk lines usually. `tcpdump` parser looks for "IP ...".
        
        let combined_output = "1: lo: <LOOPBACK...>\n2: eth0: <BROADCAST...>\n12:34:56.789000 IP 192.168.1.5 > 1.1.1.1: Flags [S]\nGET / HTTP/1.1\n";
        executor.register_output("sudo", combined_output.as_bytes());

        // Inputs:
        // 1. Prompt "Y" for sudo
        // 2. Interface Selection: "1" (eth0)
        // 3. Filter Selection: "1" (All Traffic)
        // 4. Mode Selection: "2" (Live Analysis)
        io.add_input("y\n");
        io.add_input("1\n");
        io.add_input("1\n");
        io.add_input("2\n");

        run_sniffer("", false, &executor, &io);

        let calls = executor.get_calls();
        // 1. sudo -v
        // 2. sudo ip link
        // 3. sudo tcpdump ...
        assert!(calls.len() >= 3);
        assert_eq!(calls[0].command, "sudo");
        assert_eq!(calls[0].args, vec!["-v"]);
        
        // Check for ip link call
        assert!(calls.iter().any(|c| c.args.contains(&"link".to_string())));
        // Check for tcpdump call
        assert!(calls.iter().any(|c| c.args.contains(&"tcpdump".to_string())));

        let out = io.get_output();
        assert!(out.contains("Starting All Traffic"));
    }

    #[test]
    fn test_build_sniffer_command_basic() {
        let args = vec!["-v", "-A"];
        let filter = "";
        let (cmd, args) = build_sniffer_command("tcpdump", "eth0", &args, filter, false);

        assert_eq!(cmd, "tcpdump");
        // -l is added automatically now if not present
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
