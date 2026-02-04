use std::io::{self, Write};
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

use std::sync::Arc;

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
}

impl IoHandler for CapturingIoHandler {
    fn println(&self, msg: &str) {
        let mut out = self.output.lock().unwrap();
        out.push_str(msg);
        out.push('\n');
        if self.passthrough {
            println!("{}", msg);
        }
    }

    fn print(&self, msg: &str) {
        let mut out = self.output.lock().unwrap();
        out.push_str(msg);
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
        // For testing, we might need a way to mock input for CapturingIoHandler,
        // but for now, it returns empty, effectively making interactive steps fail/skip
        // in a captured background context.
        String::new()
    }

    fn read_input(&self, _prompt: &str, default: Option<&str>) -> String {
        // Similar to read_line, background jobs generally don't take interactive input.
        // Return default if available, otherwise empty.
        default.unwrap_or("").to_string()
    }
}
