#[cfg(test)]
mod tests {
    use crate::history::{
        HistoryEntry, append_history_to_file, load_history_from_file, print_history,
    };
    use crate::io_handler::MockIoHandler;
    use std::fs;

    // Helper to create a temporary file path
    // We don't have uuid, but we can generate a random number if rand is available,
    // or just use a fixed unique-ish name.
    // Looking at Cargo.toml, we don't have rand.
    // We can use std::time
    fn get_temp_file_path_simple(suffix: &str) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("/tmp/test_history_{}_{}.json", suffix, timestamp)
    }

    #[test]
    fn test_history_entry_new() {
        let entry = HistoryEntry::new("Mode", "Target", "Status");
        assert_eq!(entry.mode, "Mode");
        assert_eq!(entry.target, "Target");
        assert_eq!(entry.status, "Status");
        // timestamp is dynamic, just check it's not empty
        assert!(!entry.timestamp.is_empty());
    }

    #[test]
    fn test_append_and_load_history() {
        let file_path = get_temp_file_path_simple("append");
        // Ensure cleanup
        let _ = fs::remove_file(&file_path);

        let entry1 = HistoryEntry::new("TestMode", "127.0.0.1", "Success");

        let res = append_history_to_file(&entry1, &file_path);
        assert!(res.is_ok());

        let loaded = load_history_from_file(&file_path).expect("Failed to load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].target, "127.0.0.1");

        let entry2 = HistoryEntry::new("TestMode2", "192.168.1.1", "Failed");
        let res = append_history_to_file(&entry2, &file_path);
        assert!(res.is_ok());

        let loaded = load_history_from_file(&file_path).expect("Failed to load");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].target, "192.168.1.1");

        // Cleanup
        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_load_non_existent_file() {
        let file_path = get_temp_file_path_simple("non_existent");
        let loaded = load_history_from_file(&file_path);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_empty());
    }

    #[test]
    fn test_load_empty_file() {
        let file_path = get_temp_file_path_simple("empty");
        let _ = fs::File::create(&file_path).unwrap();

        let loaded = load_history_from_file(&file_path);
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().is_empty());

        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn test_print_history() {
        let io = MockIoHandler::new();
        print_history(&io);
        let out = io.get_output();
        // It should print something (header or "No history")
        assert!(!out.is_empty());
    }
}
