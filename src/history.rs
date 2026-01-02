use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use chrono::{DateTime, Local};

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
            timestamp: now.format("%Y-%m-%d %H:%M:%S").to_string(),
            mode: mode.to_string(),
            target: target.to_string(),
            status: status.to_string(),
        }
    }
}

pub fn append_history(entry: &HistoryEntry) -> io::Result<()> {
    let file_path = "scan_history.json";
    let mut history = load_history()?;
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
    let file_path = "scan_history.json";
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

pub fn print_history() {
    let history = load_history().unwrap_or_default();
    if history.is_empty() {
        println!("No history found.");
        return;
    }
    
    println!("{:<20} | {:<10} | {:<20} | {:<10}", "Timestamp", "Mode", "Target", "Status");
    println!("{}", "-".repeat(70));
    for entry in history {
        println!("{:<20} | {:<10} | {:<20} | {:<10}", entry.timestamp, entry.mode, entry.target, entry.status);
    }
}
