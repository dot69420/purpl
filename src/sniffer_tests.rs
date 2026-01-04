#[cfg(test)]
mod tests {
    use crate::sniffer::{build_sniffer_command, SniffProfile, run_sniffer};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;
    use std::process::Output;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn test_run_sniffer_logic() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        // 1. Tcpdump output mock (stream)
        let output_data = "12:34:56.789000 IP 192.168.1.5 > 1.1.1.1: Flags [S]\nGET / HTTP/1.1\nHost: example.com\n";

        executor.add_stream_output(output_data);

        // Input: Select Profile ("1")
        io.add_input("1\n");

        run_sniffer("eth0", false, &executor, &io);

        let calls = executor.get_calls();
        // Should have called tcpdump
        assert!(calls.len() >= 1);
        assert_eq!(calls[0].command, "tcpdump");

        let out = io.get_output();
        assert!(out.contains("Starting General Traffic"));
    }

    #[test]
    fn test_build_sniffer_command_basic() {
        let args = vec!["-v", "-A"];
        let filter = "";
        let (cmd, args) = build_sniffer_command("tcpdump", "eth0", &args, filter);

        assert_eq!(cmd, "tcpdump");
        assert_eq!(args, vec!["-v", "-A", "-i", "eth0", "-l"]);
    }

    #[test]
    fn test_build_sniffer_command_filter() {
        let args = vec!["-v"];
        let filter = "tcp port 80";
        let (cmd, args) = build_sniffer_command("tcpdump", "wlan0", &args, filter);

        assert_eq!(cmd, "tcpdump");
        assert_eq!(args, vec!["-v", "-i", "wlan0", "-l", "tcp port 80"]);
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
