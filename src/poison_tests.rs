use crate::executor::MockExecutor;
use crate::io_handler::MockIoHandler;
use crate::poison::{PoisonProfile, build_responder_command, run_poisoning};

#[test]
fn test_run_poisoning_logic() {
    let executor = MockExecutor::new();
    let io = MockIoHandler::new();

    executor.register_success("responder");

    // Prepare input for profile selection: "2" (Basic Poisoning)
    io.add_input("2\n");

    // Run (executor defaults to root)
    run_poisoning("eth0", false, &executor, &io);

    // Verify executions
    let calls = executor.get_calls();
    assert!(calls.len() >= 2);
    assert_eq!(calls[0].args, vec!["--help"]);
    assert_eq!(calls[1].command, "responder");
    assert!(calls[1].args.contains(&"-I".to_string()));
    assert!(calls[1].args.contains(&"eth0".to_string()));

    let output = io.get_output();
    assert!(output.contains("Select Poisoning Profile"));
    assert!(output.contains("Starting Responder"));
}

#[test]
fn test_run_poisoning_logic_sudo() {
    let mut executor = MockExecutor::new();
    executor.set_root(false);
    let io = MockIoHandler::new();

    executor.register_success("sudo"); // For sudo -v
    executor.register_success("responder");

    // Input 1: "y" for sudo prompt
    io.add_input("y\n");
    // Input 2: "2" for profile
    io.add_input("2\n");

    run_poisoning("eth0", false, &executor, &io);

    let calls = executor.get_calls();
    // 1. sudo -v
    // 2. responder --help (might be wrapped in sudo? No, usually dependency check is simple exec, but let's see)
    // Actually, execute_output is used for --help check. If execute_output doesn't use sudo logic inside run_poisoning (it doesn't), it runs as user.
    // 3. sudo responder ...

    assert_eq!(calls[0].command, "sudo");
    assert_eq!(calls[0].args, vec!["-v"]);

    // The dependency check runs as 'responder --help' without sudo.
    // MockExecutor will capture this.
    assert_eq!(calls[1].command, "responder");
    assert_eq!(calls[1].args, vec!["--help"]);

    // Main execution
    assert_eq!(calls[2].command, "sudo");
    assert_eq!(calls[2].args[0], "responder");
}

#[test]
fn test_build_responder_command() {
    let flags = vec!["-w", "-r"];
    let (cmd, args) = build_responder_command("responder", "eth0", &flags, false);

    assert_eq!(cmd, "responder");
    assert_eq!(args, vec!["-I", "eth0", "-w", "-r"]);
}

#[test]
fn test_build_responder_command_sudo() {
    let flags = vec!["-w"];
    let (cmd, args) = build_responder_command("responder", "eth0", &flags, true);

    assert_eq!(cmd, "sudo");
    assert_eq!(args[0], "responder");
    assert!(args.contains(&"-I".to_string()));
}

#[test]
fn test_poison_profile_new() {
    let profile = PoisonProfile::new("Test", "Desc", &["-a"]);
    assert_eq!(profile.name, "Test");
    assert_eq!(profile.description, "Desc");
    assert_eq!(profile.flags, vec!["-a"]);
}
