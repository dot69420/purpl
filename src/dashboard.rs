use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use colored::*;
use crate::job_manager::{JobManager, JobStatus};
use crate::io_handler::IoHandler;
use crate::report::display_scan_report;

#[derive(Debug, Clone)]
pub struct DashboardItem {
    pub id: String, // Job ID or Index
    pub timestamp: String,
    pub source: String, // "Job" or "File" or "History"
    pub tool_type: String,
    pub target: String,
    pub status: String,
    pub details_path: Option<PathBuf>, // For file-based
    pub job_ref: Option<usize>, // For memory-based job ID
}

pub fn show_dashboard(job_manager: &Arc<JobManager>, io: &dyn IoHandler) {
    loop {
        let items = collect_items(job_manager);
        
        // Sort by timestamp descending (newest first)
        // Timestamp format is mixed, so sorting might be imperfect without unified parsing.
        // For now, we rely on the order of collection: Jobs (newest) -> History/Files (sorted).
        // Let's just keep the order returned by collect_items for now.

        // Pagination or Scroll?
        // Let's implement a simple list with 20 items per page if needed, or just list all.
        // Given terminal context, 20 is safe.
        
        display_list(&items, io);

        io.println("\n[ID] View Details  [R] Refresh  [0] Back");
        io.print("Select option: ");
        io.flush();
        
        let input = io.read_line().trim().to_string();
        
        if input == "0" {
            break;
        } else if input.eq_ignore_ascii_case("r") || input.is_empty() {
            continue;
        } else {
            // Try to find item by ID
            if let Some(item) = items.iter().find(|i| i.id == input) {
                view_item_details(item, job_manager, io);
            } else {
                io.println(&format!("{}", "[!] Invalid ID.".red()));
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

fn collect_items(job_manager: &Arc<JobManager>) -> Vec<DashboardItem> {
    let mut items = Vec::new();
    let mut index_counter = 1;

    // 1. Active/Recent Jobs (Memory)
    let jobs = job_manager.list_jobs();
    // Sort jobs by ID descending (newest first)
    let mut sorted_jobs = jobs.clone();
    sorted_jobs.sort_by_key(|j| j.id);
    sorted_jobs.reverse();

    for job in sorted_jobs {
        let status_lock = job.status.lock().unwrap();
        let status_str = match *status_lock {
            JobStatus::Running => "RUNNING".yellow().bold().to_string(),
            JobStatus::Completed => "COMPLETED".green().bold().to_string(),
            JobStatus::Failed => "FAILED".red().bold().to_string(),
        };
        
        // Parse name for Tool and Target (Format: "Tool Target")
        let parts: Vec<&str> = job.name.splitn(2, ' ').collect();
        let tool = parts.get(0).unwrap_or(&"Unknown").to_string();
        let target = parts.get(1).unwrap_or(&"").to_string();

        items.push(DashboardItem {
            id: format!("J{}", job.id),
            timestamp: job.start_time.clone(),
            source: "JOB".to_string(),
            tool_type: tool,
            target,
            status: status_str,
            details_path: None,
            job_ref: Some(job.id),
        });
    }

    // 2. Past Scans (Filesystem)
    // Walk scans/ directory: scans/<tool>/<target>/<date>/
    if let Ok(tools_dir) = fs::read_dir("scans") {
        for tool_entry in tools_dir.flatten() {
            if let Ok(ft) = tool_entry.file_type() {
                if !ft.is_dir() { continue; }
                let tool_name = tool_entry.file_name().to_string_lossy().to_string();
                
                // Targets
                if let Ok(targets_dir) = fs::read_dir(tool_entry.path()) {
                    for target_entry in targets_dir.flatten() {
                        if !target_entry.path().is_dir() { continue; }
                        let target_name = target_entry.file_name().to_string_lossy().to_string();

                        // Dates
                        if let Ok(dates_dir) = fs::read_dir(target_entry.path()) {
                            for date_entry in dates_dir.flatten() {
                                if !date_entry.path().is_dir() { continue; }
                                let date_name = date_entry.file_name().to_string_lossy().to_string(); // Format: YYYYMMDD_HHMMSS
                                
                                // Format timestamp nicely: YYYY-MM-DD HH:MM:SS
                                let formatted_time = if date_name.len() == 15 {
                                    format!("{}-{}-{} {}:{}:{}", 
                                        &date_name[0..4], &date_name[4..6], &date_name[6..8],
                                        &date_name[9..11], &date_name[11..13], &date_name[13..15])
                                } else {
                                    date_name.clone()
                                };

                                items.push(DashboardItem {
                                    id: format!("F{}", index_counter),
                                    timestamp: formatted_time,
                                    source: "FILE".to_string(),
                                    tool_type: tool_name.clone(),
                                    target: target_name.clone(),
                                    status: "SAVED".blue().to_string(),
                                    details_path: Some(date_entry.path()),
                                    job_ref: None,
                                });
                                index_counter += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort combined list by timestamp (descending)
    // We rely on string comparison for now as formats align (YYYY-MM-DD...)
    // Jobs (YYYY-MM-DD HH:MM:SS) vs File (YYYY-MM-DD HH:MM:SS)
    items.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    items
}

fn display_list(items: &[DashboardItem], io: &dyn IoHandler) {
    crate::ui::clear_screen();
    crate::ui::print_header(io, "PURPL CLI", Some("Task & Result Dashboard"));
    
    if items.is_empty() {
        io.println("\nNo jobs or history found.");
        return;
    }

    // Header
    io.println(&format!("{:<6} | {:<20} | {:<12} | {:<25} | {:<15}", 
        "ID", "TIMESTAMP", "TOOL", "TARGET", "STATUS"));
    io.println(&"-".repeat(90));

    // Rows
    for item in items.iter().take(30) { // Limit to 30 most recent
        // Truncate target if too long
        let target = if item.target.len() > 22 {
            format!("{}...", &item.target[..20])
        } else {
            item.target.clone()
        };

        io.println(&format!("{:<6} | {:<20} | {:<12} | {:<25} | {:<15}", 
            item.id.white().bold(), 
            item.timestamp, 
            item.tool_type.cyan(), 
            target, 
            item.status
        ));
    }
    
    if items.len() > 30 {
        io.println(&format!("... and {} more items.", items.len() - 30).italic());
    }
}

fn view_item_details(item: &DashboardItem, job_manager: &Arc<JobManager>, io: &dyn IoHandler) {
    crate::ui::clear_screen();
    crate::ui::print_header(io, "PURPL CLI", Some(&format!("Details for {}", item.id)));

    io.println(&format!("Tool: {}", item.tool_type));
    io.println(&format!("Target: {}", item.target));
    io.println(&format!("Time: {}", item.timestamp));
    io.println(&format!("Status: {}", item.status));
    io.println(&"-".repeat(40));

    if let Some(job_id) = item.job_ref {
        // Fetch from memory
        if let Some(job) = job_manager.get_job(job_id) {
            io.println(&format!("{}", "--- CONSOLE OUTPUT ---".blue()));
            io.println(&job.io.get_output());
            io.println(&format!("{}", "--- END OUTPUT ---".blue()));
        } else {
            io.println(&format!("{}", "[!] Job data expired or lost.".yellow()));
        }
    } else if let Some(path) = &item.details_path {
        // Fetch from file (using report module)
        display_scan_report(path, io);
    }

    io.print("\nPress Enter to return...");
    io.flush();
    let _ = io.read_line();
}
