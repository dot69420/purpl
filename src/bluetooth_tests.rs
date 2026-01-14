#[cfg(test)]
mod tests {
    use crate::bluetooth::{run_bluetooth_attacks, build_bluetooth_command, BtProfile};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;


    #[test]
    fn test_run_bluetooth_attacks_logic() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        executor.register_success("bluetoothctl");
        executor.register_success("rfkill");

        // Mock bluetoothctl devices output
        executor.register_output("bluetoothctl", b"bluetoothctl: 5.66\nDevice 00:11:22:33:44:55 MyDevice");

        // Input: "1" (Scan for Devices)
        io.add_input("1\n");

        run_bluetooth_attacks("", false, &executor, &io);

        let calls = executor.get_calls();
        // 1. bluetoothctl version
        // 2. rfkill
        // 3. bluetoothctl power on
        // 4. bluetoothctl scan
        // 5. bluetoothctl devices
        assert!(calls.len() >= 5);
        
        let io_out = io.get_output();
        assert!(io_out.contains("MyDevice"));
    }

    #[test]
    fn test_run_bluetooth_stress_sudo() {
        let mut executor = MockExecutor::new();
        executor.set_root(false);
        let io = MockIoHandler::new();

        executor.register_success("bluetoothctl");
        executor.register_success("rfkill");
        executor.register_success("sudo");
        executor.register_success("l2ping"); // deprecated tool check
        executor.register_success("l2ping"); // actual execution (mock behavior shared)
        
        // Input 1: "3" (Ping Flood / Stress) - this triggers root check
        io.add_input("3\n");
        // Input 2: Target MAC (Prompt comes before Sudo prompt)
        io.add_input("00:11:22:33:44:55\n");
        // Input 3: "y" (Sudo prompt)
        io.add_input("y\n");

        run_bluetooth_attacks("", false, &executor, &io);

        let calls = executor.get_calls();
        // ... deps checks ...
        // sudo -v
        // sudo l2ping ...
        
        // Find sudo calls
        let sudo_calls: Vec<_> = calls.iter().filter(|c| c.command == "sudo").collect();
        assert!(!sudo_calls.is_empty());
        assert_eq!(sudo_calls[0].args, vec!["-v"]);
        assert_eq!(sudo_calls[1].args[0], "l2ping");
    }

    #[test]
    fn test_build_bluetooth_command_scan() {
        let (cmd, args) = build_bluetooth_command("bluetoothctl", &["scan", "on"], "", false, false);
        assert_eq!(cmd, "bluetoothctl");
        assert_eq!(args, vec!["scan", "on"]);
    }

    #[test]
    fn test_build_bluetooth_command_target() {
        let (cmd, args) = build_bluetooth_command("l2ping", &["-f"], "00:11:22:33:44:55", true, false);
        assert_eq!(cmd, "l2ping");
        assert_eq!(args, vec!["-f", "00:11:22:33:44:55"]);
    }

    #[test]
    fn test_build_bluetooth_command_sudo() {
        let (cmd, args) = build_bluetooth_command("l2ping", &["-f"], "00:11:22:33:44:55", true, true);
        assert_eq!(cmd, "sudo");
        assert_eq!(args[0], "l2ping");
        assert_eq!(args[1], "-f");
    }

    #[test]
    fn test_bt_profile_new() {
        let profile = BtProfile::new("Test", "Desc", "cmd", &["-a"], true);
        assert_eq!(profile.name, "Test");
        assert_eq!(profile.description, "Desc");
        assert_eq!(profile.cmd, "cmd");
        assert_eq!(profile.args, vec!["-a"]);
        assert!(profile.requires_input);
    }
}