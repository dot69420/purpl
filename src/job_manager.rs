use crate::executor::CommandExecutor;
use crate::io_handler::{CapturingIoHandler, IoHandler};
use chrono::Local;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Debug, PartialEq)]
pub enum JobStatus {
    Running,
    Completed,
    Failed,
    Stopped,
}

pub struct Job {
    pub id: usize,
    pub name: String,
    pub status: Arc<Mutex<JobStatus>>,
    pub start_time: String,
    pub end_time: Arc<Mutex<Option<String>>>,
    pub io: CapturingIoHandler,
    pub cancelled: Arc<AtomicBool>,
}

impl Job {
    pub fn new(id: usize, name: &str, background: bool) -> Self {
        Self {
            id,
            name: name.to_string(),
            status: Arc::new(Mutex::new(JobStatus::Running)),
            start_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            end_time: Arc::new(Mutex::new(None)),
            io: CapturingIoHandler::new(!background), // Passthrough if NOT background
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_running(&self) -> bool {
        let status = self.status.lock().unwrap();
        *status == JobStatus::Running
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        let mut status = self.status.lock().unwrap();
        if *status == JobStatus::Running {
            *status = JobStatus::Stopped;
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

pub struct JobManager {
    pub jobs: Arc<Mutex<Vec<Arc<Job>>>>,
    next_id: Arc<Mutex<usize>>,
}

impl JobManager {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(Mutex::new(Vec::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    pub fn spawn_job<F>(
        &self,
        name: &str,
        task: F,
        executor: Arc<dyn CommandExecutor + Send + Sync>,
        background: bool,
    ) -> Arc<Job>
    where
        F: FnOnce(Arc<dyn CommandExecutor + Send + Sync>, &dyn IoHandler, Arc<Job>)
            + Send
            + 'static,
    {
        let mut id_lock = self.next_id.lock().unwrap();
        let id = *id_lock;
        *id_lock += 1;

        let job = Arc::new(Job::new(id, name, background));

        {
            let mut jobs_lock = self.jobs.lock().unwrap();
            jobs_lock.push(job.clone());
        }

        let job_clone = job.clone();

        thread::spawn(move || {
            // Task runs here
            task(executor, &job_clone.io, job_clone.clone());

            // Update status
            // Only set to Completed if it wasn't already Stopped/Failed
            let mut status = job_clone.status.lock().unwrap();
            if *status == JobStatus::Running {
                if job_clone.is_cancelled() {
                    *status = JobStatus::Stopped;
                } else {
                    *status = JobStatus::Completed;
                }
            }

            *job_clone.end_time.lock().unwrap() =
                Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
        });

        job
    }

    pub fn list_jobs(&self) -> Vec<Arc<Job>> {
        self.jobs.lock().unwrap().clone()
    }

    pub fn get_job(&self, id: usize) -> Option<Arc<Job>> {
        let jobs = self.jobs.lock().unwrap();
        jobs.iter().find(|j| j.id == id).cloned()
    }

    pub fn stop_job(&self, id: usize) -> bool {
        if let Some(job) = self.get_job(id) {
            job.cancel();
            return true;
        }
        false
    }

    pub fn delete_job(&self, id: usize) -> bool {
        let mut jobs = self.jobs.lock().unwrap();
        if let Some(pos) = jobs.iter().position(|j| j.id == id) {
            let job = jobs[pos].clone();
            // Ensure it's cancelled if running
            if job.is_running() {
                job.cancel();
            }
            jobs.remove(pos);
            return true;
        }
        false
    }
}

#[cfg(test)]
#[path = "job_manager_tests.rs"]
mod tests;
