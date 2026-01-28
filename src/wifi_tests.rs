#[cfg(test)]
mod tests {
    use crate::wifi::{build_wifite_command, WifiProfile, run_wifi_audit};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;


    #[test]
    fn test_run_wifi_audit_logic() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        // Register success for all intermediate tools
        executor.register_success("airmon-ng");
        executor.register_success("ip");
        executor.register_success("macchanger");
        executor.register_success("systemctl");
        executor.register_success("wifite");

        // 6. iwconfig
        executor.register_output("iwconfig", b"wlan0mon  Mode:Monitor  Frequency:2.437 GHz");

        // Input: Profile "1" (Auto-Pwn)
        io.add_input("1\n");

        run_wifi_audit("wlan0", false, &executor, &io);

        let calls = executor.get_calls();
        // 9 calls total: 
        // 1. airmon check
        // 2. ip down
        // 3. macchanger
        // 4. ip up
        // 5. airmon start
        // 6. iwconfig
        // 7. wifite
        // 8. airmon stop
        // 9. systemctl
        assert_eq!(calls.len(), 9);
        assert_eq!(calls[5].command, "iwconfig");
        assert_eq!(calls[6].command, "wifite");

        let out = io.get_output();
        assert!(out.contains("Starting WiFi Audit"));
        assert!(out.contains("Monitor mode enabled on: wlan0mon"));
    }

    #[test]
    fn test_run_wifi_audit_target_specific() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        // Register success for all intermediate tools
        executor.register_success("airmon-ng");
        executor.register_success("ip");
        executor.register_success("macchanger");
        executor.register_success("systemctl");
        executor.register_success("wifite");

        // iwconfig output
        executor.register_output("iwconfig", b"wlan0mon  Mode:Monitor  Frequency:2.437 GHz");

        // Input: Profile "5" (Target Specific)
        io.add_input("5\n");
        // Input: ESSID "TargetNet"
        io.add_input("TargetNet\n");

        run_wifi_audit("wlan0", false, &executor, &io);

        let calls = executor.get_calls();

        // Find the wifite call (should be call index 6, similar to previous test)
        assert_eq!(calls[6].command, "wifite");
        let args = &calls[6].args;

        // Verify flags
        assert!(args.contains(&"-i".to_string()));
        assert!(args.contains(&"wlan0mon".to_string()));
        assert!(args.contains(&"--kill".to_string()));
        assert!(args.contains(&"-e".to_string()));
        assert!(args.contains(&"TargetNet".to_string()));
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
