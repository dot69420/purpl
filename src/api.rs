use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::executor::CommandExecutor;
use crate::job_manager::JobManager;
use crate::nmap::{self, NmapConfig};
use crate::web::{self, WebConfig};
use crate::validation::{validate_target, validate_nmap_flags, validate_web_flags};

#[derive(Clone)]
pub struct AppState {
    pub job_manager: Arc<JobManager>,
    pub executor: Arc<dyn CommandExecutor + Send + Sync>,
}

#[derive(Serialize)]
pub struct JobResponse {
    pub id: usize,
    pub name: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct JobDetails {
    pub id: usize,
    pub name: String,
    pub status: String,
    pub start_time: String,
    pub end_time: Option<String>,
    pub output: String,
}

pub async fn serve(port: u16, job_manager: Arc<JobManager>, executor: Arc<dyn CommandExecutor + Send + Sync>) {
    let state = AppState {
        job_manager,
        executor,
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/jobs", get(list_jobs))
        .route("/jobs/:id", get(get_job))
        .route("/scan/nmap", post(trigger_nmap))
        .route("/scan/web", post(trigger_web))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    println!("Server listening on {}", addr);
    
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> &'static str {
    "OK"
}

async fn list_jobs(State(state): State<AppState>) -> Json<Vec<JobResponse>> {
    let jobs = state.job_manager.list_jobs();
    let responses = jobs.iter().map(|j| {
        let status = j.status.lock().unwrap();
        JobResponse {
            id: j.id,
            name: j.name.clone(),
            status: format!("{:?}", *status),
        }
    }).collect();
    Json(responses)
}

async fn get_job(State(state): State<AppState>, Path(id): Path<usize>) -> Result<Json<JobDetails>, StatusCode> {
    if let Some(job) = state.job_manager.get_job(id) {
        let status = job.status.lock().unwrap();
        let end_time = job.end_time.lock().unwrap();
        
        let details = JobDetails {
            id: job.id,
            name: job.name.clone(),
            status: format!("{:?}", *status),
            start_time: job.start_time.clone(),
            end_time: end_time.clone(),
            output: job.io.get_output(),
        };
        Ok(Json(details))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn trigger_nmap(
    State(state): State<AppState>,
    Json(config): Json<NmapConfig>,
) -> Result<Json<JobResponse>, (StatusCode, String)> {
    // Input Validation
    if let Err(e) = validate_target(&config.target) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid Target: {}", e)));
    }
    if let Err(e) = validate_nmap_flags(&config.profile.flags) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid Profile Flags: {}", e)));
    }
    if let Some(extras) = &config.extra_args {
         // Naive split, but good enough to check individual tokens
         let parts: Vec<String> = extras.split_whitespace().map(|s| s.to_string()).collect();
         if let Err(e) = validate_nmap_flags(&parts) {
             return Err((StatusCode::BAD_REQUEST, format!("Invalid Extra Args: {}", e)));
         }
    }

    let name = format!("API Nmap {}", config.target);
    let job_name = name.clone();
    
    let job = state.job_manager.spawn_job(
        &name,
        move |exec, io, job| {
             nmap::execute_nmap_scan(config, false, &*exec, io, Some(job));
        },
        state.executor.clone(),
        true 
    );

    let status = job.status.lock().unwrap();
    Ok(Json(JobResponse {
        id: job.id,
        name: job_name,
        status: format!("{:?}", *status),
    }))
}

async fn trigger_web(
    State(state): State<AppState>,
    Json(config): Json<WebConfig>,
) -> Result<Json<JobResponse>, (StatusCode, String)> {
    // Input Validation
    if let Err(e) = validate_target(&config.target) {
        return Err((StatusCode::BAD_REQUEST, format!("Invalid Target: {}", e)));
    }
    if let Err(e) = validate_web_flags(&config.profile.flags) {
         return Err((StatusCode::BAD_REQUEST, format!("Invalid Profile Flags: {}", e)));
    }
    if let Some(extras) = &config.extra_args {
         let parts: Vec<String> = extras.split_whitespace().map(|s| s.to_string()).collect();
         if let Err(e) = validate_web_flags(&parts) {
             return Err((StatusCode::BAD_REQUEST, format!("Invalid Extra Args: {}", e)));
         }
    }

    let name = format!("API WebEnum {}", config.target);
    let job_name = name.clone();

    let job = state.job_manager.spawn_job(
        &name,
        move |exec, io, _job| {
             web::execute_web_enum(config, false, &*exec, io);
        },
        state.executor.clone(),
        true
    );

    let status = job.status.lock().unwrap();
    Ok(Json(JobResponse {
        id: job.id,
        name: job_name,
        status: format!("{:?}", *status),
    }))
}
