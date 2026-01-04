#[cfg(test)]
mod tests {
    use crate::wifi::{build_wifite_command, WifiProfile, run_wifi_audit};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;
    use std::process::{Output, ExitStatus};
    use std::os::unix::process::ExitStatusExt;

    fn empty_output() -> Output {
        Output {
            status: ExitStatusExt::from_raw(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn test_run_wifi_audit_logic() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        // 1. check kill
        executor.add_output(empty_output());
        // 2. ip down
        executor.add_output(empty_output());
        // 3. macchanger
        executor.add_output(empty_output());
        // 4. ip up
        executor.add_output(empty_output());
        // 5. airmon start
        executor.add_output(empty_output());

        // 6. iwconfig
        let iwconfig_out = Output {
            status: ExitStatusExt::from_raw(0),
            stdout: b"wlan0mon  Mode:Monitor  Frequency:2.437 GHz".to_vec(),
            stderr: Vec::new(),
        };
        executor.add_output(iwconfig_out);

        // 7. wifite (execute) -> status
        executor.add_status(ExitStatusExt::from_raw(0));

        // 8. airmon stop
        executor.add_output(empty_output());
        // 9. systemctl start
        executor.add_output(empty_output());

        // Input: Profile "1" (Auto-Pwn)
        io.add_input("1\n");

        run_wifi_audit("wlan0", false, &executor, &io);

        let calls = executor.get_calls();
        // 9 calls total
        assert_eq!(calls.len(), 9);
        assert_eq!(calls[5].command, "iwconfig");
        assert_eq!(calls[6].command, "wifite");

        let out = io.get_output();
        assert!(out.contains("Starting WiFi Audit"));
        assert!(out.contains("Monitor mode enabled on: wlan0mon"));
    }

    #[test]
    fn test_build_wifite_command_basic() {
        let (cmd, args) = build_wifite_command("wifite", "wlan0", &["--kill"], false);
        assert_eq!(cmd, "wifite");
        assert_eq!(args, vec!["-i", "wlan0", "--kill"]);
    }

    #[test]
    fn test_build_wifite_command_sudo() {
        let (cmd, args) = build_wifite_command("wifite", "wlan0mon", &["--kill", "--wps"], true);
        assert_eq!(cmd, "sudo");
        assert_eq!(args, vec!["wifite", "-i", "wlan0mon", "--kill", "--wps"]);
    }

    #[test]
    fn test_wifi_profile_new() {
        let profile = WifiProfile::new("Test", "Desc", &["-a"]);
        assert_eq!(profile.name, "Test");
        assert_eq!(profile.description, "Desc");
        assert_eq!(profile.flags, vec!["-a"]);
    }
}
