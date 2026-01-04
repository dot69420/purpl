use crate::poison::{run_poisoning, build_responder_command, PoisonProfile};
use crate::executor::MockExecutor;
use crate::io_handler::MockIoHandler;
use std::process::{Output, ExitStatus};
use std::os::unix::process::ExitStatusExt;

#[test]
fn test_run_poisoning_logic() {
    let executor = MockExecutor::new();
    let io = MockIoHandler::new();

    // Mock 1: Check dependency 'responder --help' -> success
    let check_out = Output {
        status: ExitStatus::from_raw(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    executor.add_output(check_out);

    // Mock 2: Execution status -> success
    executor.add_status(ExitStatus::from_raw(0));

    // Prepare input for profile selection: "2" (Basic Poisoning)
    io.add_input("2\n");

    // Run (executor defaults to root)
    run_poisoning("eth0", false, &executor, &io);

    // Verify executions
    let calls = executor.get_calls();

    // 1. responder --help
    // 2. responder -I eth0 -w -r -f
    assert!(calls.len() >= 2);
    assert_eq!(calls[0].args, vec!["--help"]);
    assert_eq!(calls[1].command, "responder");
    assert!(calls[1].args.contains(&"-I".to_string()));
    assert!(calls[1].args.contains(&"eth0".to_string()));

    // Verify output
    let output = io.get_output();
    assert!(output.contains("Select Poisoning Profile"));
    assert!(output.contains("Starting Responder"));
}

#[test]
fn test_build_responder_command() {
    let flags = vec!["-w", "-r"];
    let (cmd, args) = build_responder_command("responder", "eth0", &flags);

    assert_eq!(cmd, "responder");
    assert_eq!(args, vec!["-I", "eth0", "-w", "-r"]);
}

#[test]
fn test_poison_profile_new() {
    let profile = PoisonProfile::new("Test", "Desc", &["-a"]);
    assert_eq!(profile.name, "Test");
    assert_eq!(profile.description, "Desc");
    assert_eq!(profile.flags, vec!["-a"]);
}
