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
    let mut current_page = 0;
    let page_size = 20;

    loop {
        let items = collect_items(job_manager);
        let total_items = items.len();
        let total_pages = if total_items > 0 {
            (total_items + page_size - 1) / page_size
        } else {
            1
        };

        // Ensure current_page is valid
        if current_page >= total_pages {
            current_page = if total_pages > 0 { total_pages - 1 } else { 0 };
        }

        display_list(&items, io, current_page, page_size);

        let mut options = "\n[ID] View Details  [R] Refresh  [0] Back".to_string();
        if current_page < total_pages - 1 {
            options.push_str("  [N] Next Page");
        }
        if current_page > 0 {
            options.push_str("  [P] Prev Page");
        }

        io.println(&options);
        io.print("Select option: ");
        io.flush();
        
        let input = io.read_line().trim().to_string();
        
        if input == "0" {
            break;
        } else if input.eq_ignore_ascii_case("r") || input.is_empty() {
            continue;
        } else if input.eq_ignore_ascii_case("n") {
            if current_page < total_pages - 1 {
                current_page += 1;
            }
        } else if input.eq_ignore_ascii_case("p") {
            if current_page > 0 {
                current_page -= 1;
            }
        } else {
            // Try to find item by ID
            if let Some(item) = items.iter().find(|i| i.id == input) {
                view_item_details(item, job_manager, io);
            } else {
                io.println(&format!("{}", "[!] Invalid ID or Option.".red()));
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
            JobStatus::Stopped => "STOPPED".dimmed().bold().to_string(),
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

fn display_list(items: &[DashboardItem], io: &dyn IoHandler, page: usize, page_size: usize) {
    crate::ui::clear_screen();
    crate::ui::print_header(io, "PURPL CLI", Some("Task & Result Dashboard"));
    
    if items.is_empty() {
        io.println("\nNo jobs or history found.");
        return;
    }

    let total_items = items.len();
    let total_pages = (total_items + page_size - 1) / page_size;
    let start_index = page * page_size;
    let end_index = std::cmp::min(start_index + page_size, total_items);

    io.println(&format!("Page {}/{} (Total: {})", page + 1, total_pages, total_items));

    // Header
    io.println(&format!("{:<6} | {:<20} | {:<12} | {:<25} | {:<15}", 
        "ID", "TIMESTAMP", "TOOL", "TARGET", "STATUS"));
    io.println(&"-".repeat(90));

    // Rows
    if start_index < total_items {
        for item in &items[start_index..end_index] {
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
    }
}

fn view_item_details(item: &DashboardItem, job_manager: &Arc<JobManager>, io: &dyn IoHandler) {
    loop {
        crate::ui::clear_screen();
        crate::ui::print_header(io, "PURPL CLI", Some(&format!("Details for {}", item.id)));

        io.println(&format!("Tool: {}", item.tool_type));
        io.println(&format!("Target: {}", item.target));
        io.println(&format!("Time: {}", item.timestamp));
        io.println(&format!("Status: {}", item.status));
        io.println(&"-".repeat(40));

        let mut is_running = false;

        if let Some(job_id) = item.job_ref {
            // Fetch from memory
            if let Some(job) = job_manager.get_job(job_id) {
                is_running = job.is_running();
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

        // Actions
        let mut prompt = "\n[Enter] Back".to_string();
        if is_running {
            prompt.push_str("  [S] Stop Job");
        }
        prompt.push_str("  [D] Delete");

        io.println(&prompt);
        io.print("Option: ");
        io.flush();
        let input = io.read_line().trim().to_string();

        if input.eq_ignore_ascii_case("s") && is_running {
            if let Some(job_id) = item.job_ref {
                if job_manager.stop_job(job_id) {
                     io.println(&format!("{}", "[*] Stop signal sent.".yellow()));
                } else {
                     io.println(&format!("{}", "[!] Failed to stop job.".red()));
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        } else if input.eq_ignore_ascii_case("d") {
             io.print(&format!("{}", "Are you sure you want to DELETE this item? (y/N): ".red().bold()));
             io.flush();
             let confirm = io.read_line();
             if confirm.trim().eq_ignore_ascii_case("y") {
                 if let Some(job_id) = item.job_ref {
                     if job_manager.delete_job(job_id) {
                         io.println(&format!("{}", "[*] Job deleted.".green()));
                         std::thread::sleep(std::time::Duration::from_secs(1));
                         return; // Return to list
                     }
                 } else if let Some(path) = &item.details_path {
                     if let Err(e) = fs::remove_dir_all(path) {
                         io.println(&format!("{} {}", "[!] Failed to delete files:".red(), e));
                     } else {
                         io.println(&format!("{}", "[*] Scan files deleted.".green()));
                         std::thread::sleep(std::time::Duration::from_secs(1));
                         return; // Return to list
                     }
                 }
             }
        } else if input.is_empty() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io_handler::MockIoHandler;
    use crate::executor::MockExecutor;
    use std::sync::Arc;
    use crate::job_manager::JobManager;

    #[test]
    fn test_dashboard_pagination() {
        let job_manager = Arc::new(JobManager::new());
        let executor = Arc::new(MockExecutor::new());
        let io = MockIoHandler::new();

        // Create 40 jobs
        // 40 jobs -> 20 items per page -> 2 pages
        for i in 0..40 {
            job_manager.spawn_job(&format!("Job {}", i), |_, _, _| {}, executor.clone(), true);
        }

        // Sequence of inputs:
        // 1. Initial view (Page 1) -> User inputs 'n' for Next Page
        // 2. View (Page 2) -> User inputs 'p' for Prev Page
        // 3. View (Page 1) -> User inputs '0' to Back/Exit
        io.add_input("n");
        io.add_input("p");
        io.add_input("0");

        show_dashboard(&job_manager, &io);

        let output = io.get_output();

        // Check that we have at least 2 pages
        assert!(output.contains("Page 1/"));
        assert!(output.contains("Page 2/"));

        // J40 (newest) should be on Page 1
        // J1 (oldest) should be on Page 2 (since we have 40 jobs + potential files)
        // Actually, J1 is the 40th item (or later if files are newer? No files are usually older or mixed).
        // In the debug output, J1 is on Page 2.

        // We can check that the "Next Page" option is offered on Page 1
        assert!(output.contains("[N] Next Page"));

        // We can check that "Prev Page" is offered when we are on Page 2
        // Since the output is concatenated, we should see "[P] Prev Page" somewhere.
        assert!(output.contains("[P] Prev Page"));

        // Verify flow: Page 1 -> Page 2 -> Page 1
        // We can split output by "Select option:" to analyze frames
        let frames: Vec<&str> = output.split("Select option:").collect();
        // Frame 0: Page 1
        // Frame 1: Page 2 (after 'n')
        // Frame 2: Page 1 (after 'p')
        // Frame 3: Exit prompt/result

        if frames.len() >= 3 {
            assert!(frames[0].contains("Page 1/"));
            assert!(frames[1].contains("Page 2/"));
            assert!(frames[2].contains("Page 1/"));

            // Content checks
            assert!(frames[0].contains("J40"));
            assert!(!frames[0].contains("J1 ")); // J1 should likely be on page 2 or 3

            assert!(frames[1].contains("J1 ")); // J1 is on page 2 in the debug output (items 21-40)
        }
    }
}
