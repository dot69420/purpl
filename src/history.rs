use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use chrono::{DateTime, Local};
use crate::io_handler::IoHandler;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HistoryEntry {
    pub timestamp: String,
    pub mode: String,
    pub target: String,
    pub status: String,
}

impl HistoryEntry {
    pub fn new(mode: &str, target: &str, status: &str) -> Self {
        let now: DateTime<Local> = Local::now();
        Self {
            timestamp: now.format("%d/%m/%Y %H:%M:%S").to_string(),
            mode: mode.to_string(),
            target: target.to_string(),
            status: status.to_string(),
        }
    }
}

pub fn append_history(entry: &HistoryEntry) -> io::Result<()> {
    append_history_to_file(entry, "scan_history.json")
}

pub fn append_history_to_file(entry: &HistoryEntry, file_path: &str) -> io::Result<()> {
    let mut history = load_history_from_file(file_path)?;
    history.push(entry.clone());
    
    let json = serde_json::to_string_pretty(&history)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub fn load_history() -> io::Result<Vec<HistoryEntry>> {
    load_history_from_file("scan_history.json")
}

pub fn load_history_from_file(file_path: &str) -> io::Result<Vec<HistoryEntry>> {
    if !Path::new(file_path).exists() {
        return Ok(Vec::new());
    }
    
    let mut file = fs::File::open(file_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }

    match serde_json::from_str(&content) {
        Ok(h) => Ok(h),
        Err(_) => Ok(Vec::new()), // Return empty if corrupted
    }
}

pub fn print_history(io: &dyn IoHandler) {
    let history = load_history().unwrap_or_default();
    if history.is_empty() {
        io.println("No history found.");
        return;
    }
    
    io.println(&format!("{:<20} | {:<10} | {:<20} | {:<10}", "Timestamp", "Mode", "Target", "Status"));
    io.println(&"-".repeat(70));
    for entry in history {
        io.println(&format!("{:<20} | {:<10} | {:<20} | {:<10}", entry.timestamp, entry.mode, entry.target, entry.status));
    }
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
