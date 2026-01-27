use crate::run_interactive_mode;
use crate::executor::MockExecutor;
use crate::io_handler::MockIoHandler;
use crate::job_manager::JobManager;
use std::sync::Arc;
use std::time::Duration;
use std::thread;

#[test]
fn test_interactive_mode_background_job() {
    let executor = Arc::new(MockExecutor::new());
    let io = MockIoHandler::new();
    let job_manager = Arc::new(JobManager::new());

    // Sequence:
    // 1. Select Nmap (Option 1)
    // 2. Enter Target IP
    // 3. Background? Yes (y)
    // 4. Exit (Option 10)

    io.add_input("1\n"); // Select Nmap
    io.add_input("127.0.0.1\n"); // Target
    io.add_input("1\n"); // Profile: 1 (Stealth) - Consumed by configure_nmap
    io.add_input("y\n"); // Run in background: Yes - Consumed by nmap_wrapper
    // nmap_wrapper spawns job and returns immediately (with sleep).
    // No "Press Enter" prompt for BG jobs.
    
    io.add_input("8\n"); // Exit

    // Register success for Nmap so the background job doesn't fail immediately if it runs fast
    executor.register_success("nmap");
    executor.register_success("sudo"); 
    
    run_interactive_mode(false, executor.clone(), &io, job_manager.clone());

    // Verify output contains "Job started"
    let out = io.get_output();
    assert!(out.contains("Job started in background"));

    // Verify job manager has the job
    let jobs = job_manager.list_jobs();
    assert_eq!(jobs.len(), 1);
    let job = &jobs[0];
    assert!(job.name.contains("Nmap"));
    
    // Wait a bit for the thread to potentially run
    thread::sleep(Duration::from_millis(200));
    
    let calls = executor.get_calls();
    
    if calls.is_empty() {
        println!("Job Output:\n{}", job.io.get_output());
        let status = job.status.lock().unwrap();
        println!("Job Status: {:?}", *status);
    }
    
    assert!(!calls.is_empty(), "Background job should have executed commands via MockExecutor");
}