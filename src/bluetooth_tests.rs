#[cfg(test)]
mod tests {
    use crate::bluetooth::{run_bluetooth_attacks, build_bluetooth_command, BtProfile};
    use crate::executor::MockExecutor;
    use crate::io_handler::MockIoHandler;
    use std::process::Output;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn test_run_bluetooth_attacks_logic() {
        let executor = MockExecutor::new();
        let io = MockIoHandler::new();

        // Mock 1: hcitool check success
        let check_out = Output {
            status: ExitStatusExt::from_raw(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        executor.add_output(check_out);

        // Mock 2: rfkill unblock
        executor.add_output(Output { status: ExitStatusExt::from_raw(0), stdout: vec![], stderr: vec![] });
        // Mock 3: hciconfig up
        executor.add_output(Output { status: ExitStatusExt::from_raw(0), stdout: vec![], stderr: vec![] });

        // Mock 4: execution success (scan)
        executor.add_status(ExitStatusExt::from_raw(0));

        // Input: "1" (Scan for Devices)
        io.add_input("1\n");

        run_bluetooth_attacks("", false, &executor, &io);

        let calls = executor.get_calls();
        // 1. hcitool check
        // 2. rfkill
        // 3. hciconfig
        // 4. hcitool scan
        assert!(calls.len() >= 4);
        assert_eq!(calls[3].command, "hcitool");
        assert_eq!(calls[3].args, vec!["scan"]);
    }

    #[test]
    fn test_build_bluetooth_command_scan() {
        let (cmd, args) = build_bluetooth_command("hcitool", &["scan"], "", false);
        assert_eq!(cmd, "hcitool");
        assert_eq!(args, vec!["scan"]);
    }

    #[test]
    fn test_build_bluetooth_command_target() {
        let (cmd, args) = build_bluetooth_command("l2ping", &["-f"], "00:11:22:33:44:55", true);
        assert_eq!(cmd, "l2ping");
        assert_eq!(args, vec!["-f", "00:11:22:33:44:55"]);
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
