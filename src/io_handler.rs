use std::io::{self, Write};
use std::sync::Arc;
use std::sync::Mutex;

pub trait IoHandler: Send + Sync {
    fn println(&self, msg: &str);
    fn print(&self, msg: &str);
    fn flush(&self);
    fn read_line(&self) -> String;
    fn read_input(&self, prompt: &str, default: Option<&str>) -> String;
}

pub struct RealIoHandler;

impl IoHandler for RealIoHandler {
    fn println(&self, msg: &str) {
        println!("{}", msg);
    }

    fn print(&self, msg: &str) {
        print!("{}", msg);
    }

    fn flush(&self) {
        let _ = io::stdout().flush();
    }

    fn read_line(&self) -> String {
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap_or_default();
        input
    }

    fn read_input(&self, prompt: &str, default: Option<&str>) -> String {
        let prompt_text = if let Some(def) = default {
            format!("{} [{}] ", prompt, def)
        } else {
            format!("{} ", prompt)
        };
        self.print(&prompt_text);
        self.flush();
        let input = self.read_line();
        let trimmed = input.trim();
        if trimmed.is_empty() {
            default.unwrap_or("").to_string()
        } else {
            trimmed.to_string()
        }
    }
}

pub struct MockIoHandler {
    pub output: Mutex<Vec<String>>,
    pub input_queue: Mutex<Vec<String>>,
}

impl MockIoHandler {
    pub fn new() -> Self {
        Self {
            output: Mutex::new(Vec::new()),
            input_queue: Mutex::new(Vec::new()),
        }
    }

    pub fn add_input(&self, input: &str) {
        self.input_queue.lock().unwrap().push(input.to_string());
    }

    pub fn get_output(&self) -> String {
        self.output.lock().unwrap().join("")
    }
}

impl IoHandler for MockIoHandler {
    fn println(&self, msg: &str) {
        self.output.lock().unwrap().push(format!("{}\n", msg));
    }

    fn print(&self, msg: &str) {
        self.output.lock().unwrap().push(msg.to_string());
    }

    fn flush(&self) {
        // No-op for mock
    }

    fn read_line(&self) -> String {
        let mut queue = self.input_queue.lock().unwrap();
        if !queue.is_empty() {
            queue.remove(0)
        } else {
            String::new()
        }
    }

    fn read_input(&self, prompt: &str, default: Option<&str>) -> String {
        let prompt_text = if let Some(def) = default {
            format!("{} [{}] ", prompt, def)
        } else {
            format!("{} ", prompt)
        };
        self.print(&prompt_text);

        let input = self.read_line();
        let trimmed = input.trim();
        if trimmed.is_empty() {
            default.unwrap_or("").to_string()
        } else {
            trimmed.to_string()
        }
    }
}

#[derive(Clone)]
pub struct CapturingIoHandler {
    pub output: Arc<Mutex<String>>,
    pub passthrough: bool,
}

impl CapturingIoHandler {
    pub fn new(passthrough: bool) -> Self {
        Self {
            output: Arc::new(Mutex::new(String::new())),
            passthrough,
        }
    }

    pub fn get_output(&self) -> String {
        self.output.lock().unwrap().clone()
    }

    fn enforce_limit(&self, out: &mut String) {
        // Target size: 1MB. Trigger cleanup at 1.5MB to amortize cost.
        const TARGET_SIZE: usize = 1024 * 1024;
        const CLEANUP_THRESHOLD: usize = TARGET_SIZE + (512 * 1024);

        if out.len() > CLEANUP_THRESHOLD {
            let remove_count = out.len() - TARGET_SIZE;
            let mut cut_index = remove_count;
            // Ensure we don't split a character
            while !out.is_char_boundary(cut_index) && cut_index < out.len() {
                cut_index += 1;
            }
            if cut_index < out.len() {
                out.drain(..cut_index);
            } else {
                out.clear();
            }
        }
    }
}

impl IoHandler for CapturingIoHandler {
    fn println(&self, msg: &str) {
        let mut out = self.output.lock().unwrap();
        out.push_str(msg);
        out.push('\n');
        self.enforce_limit(&mut out);
        if self.passthrough {
            println!("{}", msg);
        }
    }

    fn print(&self, msg: &str) {
        let mut out = self.output.lock().unwrap();
        out.push_str(msg);
        self.enforce_limit(&mut out);
        if self.passthrough {
            print!("{}", msg);
            let _ = io::stdout().flush();
        }
    }

    fn flush(&self) {
        if self.passthrough {
            let _ = io::stdout().flush();
        }
    }

    fn read_line(&self) -> String {
        // Background jobs don't support input directly.
        String::new()
    }

    fn read_input(&self, _prompt: &str, default: Option<&str>) -> String {
        default.unwrap_or("").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capturing_io_handler_bounded_growth() {
        let handler = CapturingIoHandler::new(false);
        let chunk = "a".repeat(1024); // 1KB
        let iterations = 10_000; // 10MB total
        for _ in 0..iterations {
            handler.print(&chunk);
        }

        // With the limit enforcement, the size should not exceed ~1.5MB + chunk size significantly
        let output = handler.get_output();
        let len = output.len();

        // Assert that we are within reasonable bounds (e.g. < 2MB)
        assert!(
            len < 2 * 1024 * 1024,
            "Buffer size {} exceeded expected limit",
            len
        );
    }

    #[test]
    fn test_capturing_io_handler_rollover() {
        let handler = CapturingIoHandler::new(false);
        // Fill up to limit
        let big_chunk = "x".repeat(1024 * 1024); // 1MB
        handler.print(&big_chunk);

        // Add more
        handler.print("END");

        // Trigger pruning.
        let overflow = "y".repeat(600 * 1024); // 600KB
        handler.print(&overflow);

        let output = handler.get_output();
        assert!(
            output.len() <= 1024 * 1024 + 1024,
            "Output should be close to 1MB, got {}",
            output.len()
        );

        let expected_end = "END".to_owned() + &overflow;
        assert!(output.ends_with(&expected_end));
    }
}
