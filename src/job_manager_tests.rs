use super::*;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use crate::executor::MockExecutor;

#[test]
fn test_spawn_and_complete_job() {
    let job_manager = JobManager::new();
    let executor = Arc::new(MockExecutor::new());

    job_manager.spawn_job("Test Job", |_, io, _| {
        io.println("Job output");
        thread::sleep(Duration::from_millis(50));
    }, executor, true);

    let jobs = job_manager.list_jobs();
    assert_eq!(jobs.len(), 1);
    
    let job = &jobs[0];
    assert_eq!(job.name, "Test Job");
    assert!(job.is_running());

    // Wait for completion
    thread::sleep(Duration::from_millis(100));
    
    let status = job.status.lock().unwrap();
    assert_eq!(*status, JobStatus::Completed);
    
    let output = job.io.get_output();
    assert_eq!(output.trim(), "Job output");
}

#[test]
fn test_multiple_jobs() {
    let job_manager = JobManager::new();
    let executor = Arc::new(MockExecutor::new());

    job_manager.spawn_job("Job 1", |_, _, _| {}, executor.clone(), true);
    job_manager.spawn_job("Job 2", |_, _, _| {}, executor.clone(), true);

    let jobs = job_manager.list_jobs();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0].id, 1);
    assert_eq!(jobs[1].id, 2);
}

#[test]
fn test_get_job() {
    let job_manager = JobManager::new();
    let executor = Arc::new(MockExecutor::new());

    job_manager.spawn_job("Job 1", |_, _, _| {}, executor, true);

    let job = job_manager.get_job(1);
    assert!(job.is_some());
    assert_eq!(job.unwrap().name, "Job 1");

    let no_job = job_manager.get_job(99);
    assert!(no_job.is_none());
}