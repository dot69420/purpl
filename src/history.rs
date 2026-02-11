use crate::io_handler::IoHandler;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

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
    if is_legacy_format(file_path) {
        let mut history = load_history_from_file(file_path)?;
        history.push(entry.clone());

        let mut file = fs::File::create(file_path)?;
        for item in history {
            let json = serde_json::to_string(&item)?;
            writeln!(file, "{}", json)?;
        }
    } else {
        let json = serde_json::to_string(entry)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(file_path)?;
        writeln!(file, "{}", json)?;
    }
    Ok(())
}

fn is_legacy_format(file_path: &str) -> bool {
    if let Ok(file) = fs::File::open(file_path) {
        let mut reader = BufReader::new(file);
        // Skip whitespace to find the first meaningful character
        let mut buf = [0; 1];
        loop {
            match reader.read(&mut buf) {
                Ok(1) => {
                    if !buf[0].is_ascii_whitespace() {
                        return buf[0] == b'[';
                    }
                }
                _ => return false, // EOF or Error
            }
        }
    }
    false
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

    // Check if it's a JSON array (legacy)
    if content.trim_start().starts_with('[') {
        match serde_json::from_str(&content) {
            Ok(h) => Ok(h),
            Err(_) => Ok(Vec::new()), // Return empty if corrupted
        }
    } else {
        // Assume JSONL
        let mut history = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() { continue; }
            if let Ok(entry) = serde_json::from_str::<HistoryEntry>(line) {
                history.push(entry);
            }
        }
        Ok(history)
    }
}

pub fn print_history(io: &dyn IoHandler) {
    let history = load_history().unwrap_or_default();
    if history.is_empty() {
        io.println("No history found.");
        return;
    }

    io.println(&format!(
        "{:<20} | {:<10} | {:<20} | {:<10}",
        "Timestamp", "Mode", "Target", "Status"
    ));
    io.println(&"-".repeat(70));
    for entry in history {
        io.println(&format!(
            "{:<20} | {:<10} | {:<20} | {:<10}",
            entry.timestamp, entry.mode, entry.target, entry.status
        ));
    }
}

#[derive(Serialize, Deserialize)]
struct LastTarget {
    target: String,
}

#[allow(dead_code)]
pub fn get_last_target() -> Option<String> {
    let path = "last_target.json";
    if !Path::new(path).exists() {
        return None;
    }
    match fs::read_to_string(path) {
        Ok(content) => {
            if let Ok(data) = serde_json::from_str::<LastTarget>(&content) {
                if !data.target.is_empty() {
                    return Some(data.target);
                }
            }
            None
        }
        Err(_) => None,
    }
}

pub fn save_last_target(target: &str) {
    if target.trim().is_empty() {
        return;
    }
    let data = LastTarget {
        target: target.to_string(),
    };
    if let Ok(json) = serde_json::to_string(&data) {
        let _ = fs::write("last_target.json", json);
    }
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
